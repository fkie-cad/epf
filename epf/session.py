import csv
import json
import os
import sys
import threading
import time
from numpy import random

from epf import Target, exception
from epf.restarters import IRestarter
from . import helpers
from . import shm
from . import constants
from epf.graph import Graph
from typing import Dict, Any, Tuple

from .testcase import TestCase
from epf.prompt.session_prompt import SessionPrompt


class SessionOptions(object):
    """
    This is a dumb, auxiliary class to save all session options
    """

    def __init__(self, *args, **kwargs):
        self.__dict__.update(kwargs)


class SessionClock(object):
    def __init__(self, time_budget: float = 0.0):
        self._budget = time_budget
        self._execution_time = 0.0
        self._start = 0.0
        self._stop = 0.0
        self._running = False

    @property
    def exhausted(self):
        return self._budget > 0 >= self._budget - self._execution_time

    @property
    def execution_time(self):
        return self._execution_time

    @property
    def budget(self):
        return self._budget

    def start(self):
        if self._running:
            return
        self._start = time.time()
        self._running = True

    def stop(self):
        if not self._running:
            return
        self._stop = time.time()
        self._execution_time += self._stop - self._start
        self._running = False


class Session(object):
    """
    Implements main fuzzing functionality, contains all configuration parameters, etc.

    Args:
        restart_sleep_time (float): Time in seconds to sleep when target can't be restarted. Default 5.
        target (Target):        Target for fuzz session. Target must be fully initialized. Default None.
        restarter (IRestarter): Restarter module initialized. Will call restart() when the target is down. Default None
    """

    def __init__(self,
                 restart_sleep_time: float = 5.0,
                 target: Target = None,
                 restarter: IRestarter = None,
                 seed: int = 0,
                 fuzz_protocol: "IFuzzer" = None,
                 alpha: float = 0.0,
                 beta: float = 0.0,
                 population_limit: int = 10000,
                 time_budget: float = 0.0,
                 post_relax: bool = True,
                 debug: bool = False,
                 output: str = "",
                 dump_shm: bool = False,
                 deterministic: bool = False,
                 ):
        super().__init__()

        self.opts = SessionOptions(
            restart_sleep_time=restart_sleep_time,
            # Transmission Options
            host=target.target_connection.host,
            port=target.target_connection.port,
            send_timeout=target.target_connection._send_timeout,
            recv_timeout=target.target_connection._recv_timeout,
            pcap=fuzz_protocol.pcap_file,
            seed=seed,
            alpha=alpha,
            beta=beta,
            population_limit=population_limit,
            time_budget=time_budget,
            post_relax=post_relax,
            debug=debug,
            output=output,
            dump_shm=dump_shm,
            deterministic=deterministic,
        )

        self.fuzz_protocol = fuzz_protocol

        self.target = target
        if target is not None:
            try:
                self.add_target(target)
            except exception.EPFRpcError as e:  # TODO: Change exception
                raise
        self._requests = []
        self.graph = Graph()

        self.suspects = []

        self.restarter = restarter
        self.restarter.restart(planned=True)
        # self.restarter.suspend() TODO

        # Some variables that will be used during fuzzing
        self.time_budget = SessionClock(time_budget)
        self.test_case_cnt = 0
        self.populations = self.fuzz_protocol.get_populations(self)
        self.population_iterator = iter(sorted(self.populations.keys()))
        self.active_population = self.populations[next(self.population_iterator)]
        self.drain_seed_iterator = iter(self.active_population)
        self.active_individual = None
        self.active_testcase = None
        self.previous_testcase = None
        self.drain_seed_individuals = True

        self.is_paused = False
        self.prompt = None
        self.energy = 1.0
        self.energy_threshold = 0.05
        self.energy_periods = 0
        self.reheat_count = 0

        # Create Results Dir if it does not exist
        self.result_dir = os.path.join('epf-results', f'{int(time.time())}')
        if self.opts.output != "":
            self.result_dir = self.opts.output
        self.transition_payload_dir = os.path.join(self.result_dir, 'transition_payloads')
        self.bug_payload_dir = os.path.join(self.result_dir, 'bug_payloads')
        helpers.mkdir_safe(self.result_dir)
        helpers.mkdir_safe(self.transition_payload_dir)
        self.write_run_json()
        for p in iter(sorted(self.populations.keys())):
            helpers.mkdir_safe(os.path.join(self.transition_payload_dir, p))
            helpers.mkdir_safe(os.path.join(self.bug_payload_dir, p))
        self.bugs_csv = None
        self.bugs_csv_writer = None
        self.debug_csv = None
        self.debug_csv_writer = None
        self.prepare_bugs_csv()
        self.opts.debug = debug
        if self.opts.debug:
            self.prepare_debug_csv()
        self.update_bug_db = False
        self.t_last_increase = time.time()
        self.test_case_buffer = []

    def write_run_json(self):
        json_file = os.path.join(self.result_dir, "run.json")
        mem = shm.get()
        mem.acquire()

        data = {
            "general": {
                "fuzzer": self.fuzz_protocol.name,
                "time_budget": self.time_budget.budget,
                "random_seed": self.opts.seed,
                "output": self.result_dir,
                "debug": self.opts.debug,
                "dump_shm": self.opts.dump_shm,
                "deterministic": self.opts.deterministic,
                "dtrace": constants.TRACE,
                "batch": constants.BATCH,
                "shm_overwrite": constants.SHM_OVERWRITE,
            },
            "target": {
                "exec_command": self.restarter.cmd,
                "protocol": self.target.target_connection.proto,
                "connection": f'{self.target.target_connection.host}:{self.target.target_connection.port}',
                "send_timeout": self.opts.send_timeout,
                "recv_timeout": self.opts.recv_timeout,
            },
            "instrumentation": {
                "mmap_id": mem.name,
                "injection_env": constants.INSTR_AFL_ENV,
                "mem_size": mem.size / 1024,
            },
            "genetics": {
                "populations": {
                    "seed": self.opts.pcap,
                    "count": len(self.populations),
                    "population_names": [p for p in iter(sorted(self.populations.keys()))],
                    "population_sizes": [len(self.populations[p]) for p in iter(sorted(self.populations.keys()))],
                    "population_limit": self.opts.population_limit,
                },
                "simulated_annealing": {
                    "cooldown_alpha": self.opts.alpha,
                    "reheat_beta": self.opts.beta,
                    "spot_mutation_probability": self.active_population._p_mutation,
                },
            },
        }
        mem.release()
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

    def prepare_bugs_csv(self):
        b_file = os.path.join(self.result_dir, 'bugs.csv')
        self.bugs_csv = open(b_file, "w")
        header = [
            "bug_id",
            "timestamp",
            "iteration",
            "test_id",
            "individual",
            "increased_coverage",
            "caused_restart",
            "cause_of_restart",
            "exit_code",
            "reported_coverage",
            "population",
            "population_size",
            "energy",
            "energy_period"
        ]
        self.bugs_csv_writer = csv.DictWriter(self.bugs_csv, fieldnames=header)
        self.bugs_csv_writer.writeheader()
        self.bugs_csv.flush()

    def prepare_debug_csv(self):
        d_file = os.path.join(self.result_dir, 'debug.csv')
        self.debug_csv = open(d_file, "w")
        header = [
            "timestamp",
            "iteration",
            "test_id",
            "individual",
            "increased_coverage",
            "caused_restart",
            "cause_of_restart",
            "exit_code",
            "reported_coverage",
            "population",
            "population_size",
            "energy",
            "energy_period"
        ]
        self.debug_csv_writer = csv.DictWriter(self.debug_csv, fieldnames=header)
        self.debug_csv_writer.writeheader()
        self.debug_csv.flush()

    def cooldown(self) -> float:
        self.energy *= self.opts.alpha
        return self.energy

    def reheat(self) -> float:
        self.reheat_count += 1
        self.energy = min(1.0, self.energy / self.opts.beta)
        return self.energy

    def start(self):
        """
        Starts the prompt once the session is prepared
        """
        if not constants.BATCH:
            self.prompt = SessionPrompt(self)
            self.prompt.start_prompt()
        else:
            self.is_paused = False
            t = threading.Thread(target=self.run_all)
            t.start()
            t.join()
            self.restarter.kill()
            self.bugs_csv.flush()
            self.bugs_csv.close()
            if self.opts.debug:
                self.debug_csv.flush()
                self.debug_csv.close()
            if self.opts.dump_shm:
                sp = os.path.join(self.result_dir, 'shm.bin')
                with open(sp, 'wb') as dst:
                    mem = shm.get()
                    mem.acquire()
                    dst.write(mem.buf)
                    mem.release()
                    mem.close()

    # --------------------------------------------------------------- #

    def schedule_population(self):
        if self.energy <= self.energy_threshold:
            key = next(self.population_iterator, None)
            if key is None:
                # reset
                self.population_iterator = iter(sorted(self.populations.keys()))
                self.energy_periods += 1
                key = next(self.population_iterator)
            self.active_population = self.populations[key]
            self.energy = 1.0
            # if self.energy_periods > 0:
            #     self.active_population.reseed(self.opts.population_limit)
        self.cooldown()

    def generate_individual(self):
        self.active_individual = self.active_population.new_child()

    def evaluate_individual(self):
        # 1. create test case
        self.test_case_cnt += 1
        self.previous_testcase = self.active_testcase
        self.active_testcase = TestCase(id=self.test_case_cnt, session=self, individual=self.active_individual)
        self.test_case_buffer += [self.active_testcase]
        if len(self.test_case_buffer) > 10:
            self.test_case_buffer.pop(0)
        if not self.restarter.healthy():
            self.update_bugs(Exception("uncertain"))
        err, executed = self.active_testcase.run()
        return err, executed


    def update_population(self, err, executed) -> bool:
        crashed = not self.restarter.healthy()
        if (crashed or not executed) and not isinstance(err, exception.EPFPaused):
            self.update_bugs(err)
        cov = self.active_testcase.coverage_snapshot
        change = cov != self.previous_testcase.coverage_snapshot if self.previous_testcase is not None else True
        if constants.TRACE:
            print(f"cov_trace, {self.test_case_cnt}, {cov}, {change}", file=sys.stderr)
        if change:
            self.t_last_increase = time.time()
            self.active_testcase.coverage_increase = True
            self.reheat()
            self.active_population.update(self.active_individual, heat=self.energy, add=change)
        else:
            self.active_population.update(self.active_individual, heat=self.energy, add=random.random() <= self.energy)
        self.active_population.shrink(self.opts.population_limit)
        return True

    def update_bugs(self, err: Exception):
        retval = self.restarter.kill()
        self.restarter.restart()
        for tcs in self.test_case_buffer:
            tcs.add_error(err)
            tcs.needed_restart = True
            tcs.exit_code = int(retval)
            self.suspects += [tcs]
            row = {
                "bug_id": len(self.suspects),
                "timestamp": round(self.time_budget.execution_time, 2),
                "iteration": self.test_case_cnt,
                "test_id": tcs.name,
                "individual": tcs.individual.identity,
                "increased_coverage": tcs.coverage_increase,
                "caused_restart": tcs.needed_restart,
                "cause_of_restart": str(tcs.errors[-1]),
                "exit_code": tcs.exit_code,
                "reported_coverage": tcs.coverage_snapshot,
                "population": tcs.individual.species,
                "population_size": len(self.populations[tcs.individual.species]),
                "energy": self.energy,
                "energy_period": self.energy_periods
            }
            self.bugs_csv_writer.writerow(row)
            self.bugs_csv.flush()
            with open(os.path.join(self.bug_payload_dir, tcs.individual.species, str(tcs.individual.identity)), "wb") as f:
                f.write(tcs.individual.serialize())
                f.flush()
        self.test_case_buffer = []

    def debug(self):
        if not self.opts.debug:
            return
        tc: TestCase = self.active_testcase
        row = {
            "timestamp": round(self.time_budget.execution_time, 2),
            "iteration": self.test_case_cnt,
            "test_id": tc.name,
            "individual": tc.individual.identity,
            "increased_coverage": tc.coverage_increase,
            "caused_restart": tc.needed_restart,
            "cause_of_restart": str(tc.errors[-1]) if len(tc.errors) != 0 else "-",
            "exit_code": tc.exit_code if len(tc.errors) != 0 else 0,
            "reported_coverage": tc.coverage_snapshot,
            "population": tc.individual.species,
            "population_size": len(self.populations[tc.individual.species]),
            "energy": self.energy,
            "energy_period": self.energy_periods
        }
        # with open(os.path.join(self.bug_payload_dir, tc.individual.species, str(tc.individual.identity)), "wb") as f:
        #     f.write(tc.individual.serialize())
        #     f.flush()
        self.debug_csv_writer.writerow(row)
        self.debug_csv.flush()

    def cont(self) -> bool:
        """
        Cont outputs a boolean indicating whether a new fuzz iteration should be processed.

        Currently, this method depends on the time budget and the epf shell pause
        between fuzzing iterations. If the time budget expired or the epf shell has
        been requested, this method returns false.

        Furthermore, cont() is a checkpoint for time budget measurements and updates.
        Each call, the time difference is being calculated.

        @return: bool
        """
        self.time_budget.stop()
        if self.time_budget.exhausted:
            self.is_paused = True
        result = not (self.time_budget.exhausted or self.is_paused)
        if int(self.time_budget.execution_time) % 10 == 0 and constants.BATCH:
            print(f"{self.time_budget.execution_time}/{self.time_budget.budget}")
        if result:
            self.time_budget.start()
        return result

    def drain(self):
        while not self.is_paused:
            self.active_individual = next(self.drain_seed_iterator, None)
            if self.active_individual is None:
                key = next(self.population_iterator, None)
                if key is None:
                    # reset
                    self.population_iterator = iter(sorted(self.populations.keys()))
                    self.drain_seed_individuals = False
                    return
                self.active_population = self.populations[key]
                self.drain_seed_iterator = iter(self.active_population)
                continue
            self.evaluate_individual()
            self.restarter.kill(ignore=True)
            self.restarter.restart(planned=True)
            self.debug()

    def run_all(self):
        if self.drain_seed_individuals:
            self.drain()
        #########
        while self.cont():                                      # while CONTINUE(C)
            self.schedule_population()                          #   conf <- SCHEDULE(C, t_elapsed, t_limit)
            self.generate_individual()                          #   tcs  <- INPUTGEN(conf)
            err, executed = self.evaluate_individual()
            self.update_population(err, executed)
            # retry = False
            # while True:
            #    # retry
            #    failed = self.evaluate_individual(retry=retry)  #   B', execinfos <- INPUTEVAL(conf, tcs, O_bug)
            #    retry = not self.update_population(failed)      #   C <- CONFUPDATE(C', conf, execinfos)
            #    if not retry:
            #        break
            #    if constants.TRACE:
            #        print(f"retry, {self.test_case_cnt}", file=sys.stderr)
            # self.update_bugs()                                  #   B <- B u B'
            ##################
            self.debug()

    # ================================================================#
    # Suspects, disabled elements                                     #
    # ================================================================#

    # def add_current_case_as_suspect(self, error: Exception, complications: bool, exit_code: int):
    #     self.add_suspect(self.active_testcase, error, complications, exit_code)

    # def add_last_case_as_suspect(self, error: Exception, complications: bool, exit_code: int):
    #     if self.previous_testcase is None:
    #         return
    #     self.add_suspect(self.previous_testcase, error, complications, exit_code)

    # def add_suspect(self, testcase: TestCase, error: Exception, complications: bool, exit_code: int):
    #     self.update_bug_db = True
    #     testcase.add_error(error)
    #     testcase.needed_restart = complications
    #     testcase.exit_code = exit_code
    #     self.suspects += [testcase]

    def add_target(self, target: Target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        Args:
            target: Target to add to session
        """

        # add target to internal list.
        self.target = target
