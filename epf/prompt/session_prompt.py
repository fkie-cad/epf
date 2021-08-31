import os
import sys
import signal
import threading
import time

import hexdump
import array
import matplotlib.pyplot as plt
import subprocess
from typing import TYPE_CHECKING
from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.styles import Style, merge_styles

from epf import constants
from epf import exception

from .prompt import CommandPrompt
from . import stats
from ..constants import INSTR_AFL_MAP_SIZE
from .. import shm

if TYPE_CHECKING:
    from epf.session import Session


class SessionPrompt(CommandPrompt):

    def __init__(self, session: 'Session'):
        super().__init__()
        self.session: 'Session' = session
        signal.signal(signal.SIGINT, self._signal_handler)

    # ================================================================#
    # CommandPrompt Overridden Functions                              #
    # ================================================================#

    def get_commands(self):
        """ Contains the full list of commands"""
        commands = super().get_commands()
        commands.update({
            'info': {
                'desc': 'Show Session Information',
                'exec': self._cmd_info,
            },
            # TODO: more insights
            # 'poc': {
            #     'desc': 'Print the python poc code of test case by index',
            #     'exec': self.cmd_print_poc_test_case
            # },
            'suspects': {
                'desc': 'print information about the tests suspected of crashing something',
                'exec': self._cmd_suspects
            },
            # 'suspects-del': {
            #     'desc': 'delete suspect',
            #     'exec': self.cmd_delsuspect
            # },
            # 'restart': {
            #     'desc': 'Launch the restarter module to restart the target',
            #     'exec': self.cmd_restart
            # },
            'graph': {
                'desc': 'graph',
                'exec': self._cmd_graph
            },
            'ishowmem': {
                'desc': 'Take a snapshot of the AFL-instrumentation\'s shared memory. -> ishowmem [start] [offset]',
                'exec': self._cmd_ishowmem
            },
            'idumpmem': {
                'desc': 'Take a snapshot of the AFL-instrumentation\'s shared memory and dump it to file -> idumpmem'
                        '<filepath>',
                'exec': self._cmd_idumpmem
            },
            # 'energy': {
            #     'desc': 'Energy Plotting',
            #     'exec': self._cmd_energy
            # },
        })
        return commands

    # --------------------------------------------------------------- #

    def get_prompt(self):
        host = self.session.target.target_connection.host
        port = str(self.session.target.target_connection.port)

        return HTML('[<testn>#</testn>] '
                    '<b>➜</b> <host>{}</host>:<port>{}</port> $ '
                    .format(host, port))

    # --------------------------------------------------------------- #

    def bottom_toolbar(self):
        elapsed = round(self.session.time_budget.execution_time, 2)
        budget = round(self.session.time_budget.budget, 2)
        toolbar_message = HTML(f'<bttestn>{self.session.fuzz_protocol.name}</bttestn> <b>&gt;</b> '
                               f'Iterations: <bttestn>{self.session.test_case_cnt}</bttestn>'
                               f'| ExecTime (s): <bttestn>{elapsed}</bttestn>/<bttestn>{budget}</bttestn> '
                               f'| Population: <bttestn>{self.session.active_population.species}</bttestn> ')
        return toolbar_message

    # --------------------------------------------------------------- #

    def handle_break(self, tokens: list) -> bool:
        if tokens[0] in ('c', 'continue'):
            self.session.is_paused = False

            s = stats.Stats()
            s.set_session(self.session)
            t = threading.Thread(target=self.session.run_all)
            t.start()
            s.run(fork=False)
            self.session.is_paused = True
            t.join()
            print_formatted_text(HTML(' <testn>Pausing...</testn>'),
                                 style=self.get_style())
            self.session.is_paused = True
            return True
        else:
            return False

    # --------------------------------------------------------------- #

    def handle_exit(self, tokens: list) -> None:
        if len(tokens) > 0:
            if tokens[0] in ('exit', 'quit', 'q'):
                self.exit_message()
                sys.exit(0)

    # --------------------------------------------------------------- #

    def _signal_handler(self, _signal, frame):
        pass

    # --------------------------------------------------------------- #

    def _print_color(self, color, message):
        print_formatted_text(HTML(f'<{color}>{message}</{color}>'),
                             style=self.get_style())

    # --------------------------------------------------------------- #

    def _print_error(self, message):
        self._print_color('red', message)

    # ================================================================#
    # Command handlers                                                #
    # ================================================================#

    def _cmd_info(self, _):
        if self.session.active_population is None:
            print("No stats to show...session hasn't been initialized..")
            return
        s = stats.Stats()
        s.set_session(self.session)
        s.run(fork=False)

    def _cmd_suspects(self, _):
        for suspect in self.session.suspects:
            print(suspect)

    def _cmd_print_test_case(self, tokens):
        try:
            test_case_index = int(tokens[0])
        except IndexError:  # No index specified, print actual case
            if self.session.test_case is not None:
                self.session.test_case.print_requests()
            return
        except ValueError:
            self._print_error('print usage: print [TEST_ID]')
            return
        session_state = self.session.save_session_state()
        self.session.goto(test_case_index)
        if self.session.test_case is not None:
            self.session.test_case.print_requests()
        self.session.load_session_state(session_state)

    def _cmd_print_poc_test_case(self, tokens):
        try:
            test_case_index = int(tokens[0])
        except IndexError: # No index specified, print actual case
            if self.session.test_case is not None:
                self.session.test_case.print_poc()
            return
        except ValueError:
            self._print_error('poc usage: poc [TEST_ID]')
            return
        session_state = self.session.save_session_state()
        self.session.goto(test_case_index)
        if self.session.test_case is not None:
            self.session.test_case.print_poc()
        self.session.load_session_state(session_state)

    # --------------------------------------------------------------- #

    # def _cmd_suspects(self, tokens):
    #     try:
    #         test_case_index = int(tokens[0])
    #         suspect = self.session.suspects[test_case_index]
    #         print(suspect.info())
    #     except IndexError:  # No index specified, Show all suspects
    #         for suspect_id, suspect in self.session.suspects.items():
    #             if suspect is not None:
    #                 print(suspect.info())
    #             else:
    #                 print(f'Test Case {suspect_id}')
    #         return
    #     except ValueError:
    #         self._print_error('suspects usage: suspects [TEST_ID]')
    #         return
    #     except KeyError:
    #         self._print_error(f'Suspect with id {tokens[0]} not found')

    def _cmd_delsuspect(self, tokens):
        try:
            test_case_index = int(tokens[0])
            suspect = self.session.suspects.pop(test_case_index)
            print(f'Removing {suspect} from suspects')
        except IndexError:  # No index specified, Show all suspects
            self._print_error('delsuspect usage: delsuspect TEST_ID')
            return
        except ValueError:
            self._print_error('delsuspect usage: delsuspect TEST_ID')
            return
        except KeyError:
            self._print_error(f'Suspect with id {tokens[0]} not found')

    # --------------------------------------------------------------- #

    def _cmd_restart(self, _):
        """
        Launch the restarter module of the session, if a restarter module was set
        """
        self.session.restart_target()

    # --------------------------------------------------------------- #

    def get_style(self):
        return merge_styles([super().get_style(), Style.from_dict(constants.STYLE)])

    # --------------------------------------------------------------- #

    def intro_message(self):
        print_formatted_text(HTML('Fuzzing paused! Welcome to the <b>EPF Shell</b>'))

    # --------------------------------------------------------------- #

    def exit_message(self):
        self.session.restarter.kill()
        self.session.bugs_csv.flush()
        self.session.bugs_csv.close()
        mem = shm.get()
        mem.acquire()
        mem.close()
        mem.release()
        if self.session.opts.debug:
            self.session.debug_csv.flush()
            self.session.debug_csv.close()
        print_formatted_text(HTML('<b>Exiting prompt...</b>'))

    # --------------------------------------------------------------- #

    def _cmd_graph(self, tokens):
        self.session.graph.visualize()


    def _cmd_ishowmem(self, tokens):
        """
        Print a snapshot of the afl instrumentation's shared memory.
        :param tokens: list of args -> memsnap [start] [offset]
        :return: None
        """
        start = 0
        stop = 0
        try:
            start = 0 if len(tokens) < 1 else int(int(tokens[0], 0) / 16)
            stop = int(INSTR_AFL_MAP_SIZE / 16) if len(tokens) < 2 else int(int(tokens[1], 0) / 16 + start)
        except ValueError:
            pass
        hdr = ('Base', *(x for x in range(0, 16)), 'ASCII')
        try:
            less = subprocess.Popen(["less"], stdin=subprocess.PIPE);
            less.stdin.write(('{:10}' + ('{:02X} ' * 8 + ' ') * 2 + '{}').format(*hdr).encode(encoding='utf-8'))
            less.stdin.write(b'\n' + b'-' * 76 + b'\n')
            mem = shm.get()
            mem.acquire()
            for i, line in enumerate(hexdump.hexdump(data=mem.buf, result='generator')):
                if start <= i < stop:
                    less.stdin.write(line.encode(encoding='utf-8'))
                    less.stdin.write(b'\n')
            mem.release()
            less.stdin.close()
            less.wait()
        except BrokenPipeError:
            pass

    # --------------------------------------------------------------- #

    def _cmd_idumpmem(self, tokens):
        """
        Dump a snapshot of the afl instrumentation's shared memory right into a binary file
        :param tokens: list of args -> memdump <filepath>
        :return: None
        """
        if len(tokens) < 1:
            self._print_error("missing filepath parameter")
            return
        filepath = tokens[0]
        try:
            with open(filepath, 'wb') as fd:
                mem = shm.get()
                mem.acquire()
                clone = bytearray(array.array('B', mem.buf))
                mem.release()
                fd.write(clone)
                fd.flush()
                self._print_color('green', 'Dumped {} bytes shared memory into \'{}\''.format(len(clone), filepath))
        except IOError as io:
            self._print_error(io)

    # ---------------------------------------------------------------
