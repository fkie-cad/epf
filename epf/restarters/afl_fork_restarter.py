import subprocess
import time

import psutil

from .irestarter import IRestarter
from ..constants import INSTR_AFL_ENV
from .. import shm
import shlex
import os


class AFLForkRestarter(IRestarter):
    """
    AFLForkRestarter is a restarter module that implements an execve(3) forkserver that may be
    used in conjunction with AFL-LLVM-instrumented binaries.

    In order for the Instrumentation to properly communicate with Fuzzowski, shared memory is required.
    This technical white paper
        https://github.com/AFLplusplus/AFLplusplus/blob/master/docs/technical_details.md
    explains that the instrumented binary expects to receive a predefined environment variable
    (default: '__AFL_SHM_ID') containing a linux shared memory identifier. Using this input,
    the process attaches to the existing memory and writes information to it.

    Consequently, it is up to the forking parent to allocate, manage and finally free shared memory.
    Due to Fuzzowski's architecture, this module does (at its worst) create shared memory if not already done.

    Note: it does NOT employ the method that has been discussed in
            http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html !
          The intended design in Fuzzowski is not to restart the binary each time it has been
          fed with input. Thus, the resulting overhead that comes with simply forking the target
          is considered to be acceptable.
    """

    def __init__(self, cmd, *args, **kwargs):
        """
        Constructor

        :param cmd: Command including params that will be executed
        :param args: ignored
        :param kwargs: ignored
        """
        # the command to execute
        self.cmd = cmd
        # execve(3) params
        self._argv = shlex.split(self.cmd)
        self._path = self._argv[0]
        self.process = None
        self.restarts = 0
        self.crashes = 0

    @staticmethod
    def name() -> str:
        """
        This module's name

        :return: name
        """
        return 'afl_fork'

    @staticmethod
    def help() -> str:
        """
        This module's help

        :return: help str
        """
        return "'<executable> [<argument> ...]' (Pass command and arguments within quotes, as only one argument)"

    def restart(self, *args, planned=False) -> bool:
        """
        Restarts the target

        :param args: ignored
        :param kwargs: ignored
        :return: bool
        """
        try:
            mem = shm.get()
            mem.acquire()
            identifier = mem.name  # get instrumentation shared memory id
            mem.release()
            environ = _update_env(identifier)  # add pseudorandom shm identifier to environment variable of child process
            cid = self._fork(environ)  # actually fork
            self.process = psutil.Process(cid)
            if not self._wait_for_status(psutil.STATUS_SLEEPING, timeout=5.0):
                return False
        except Exception as e:
            return False
        if not planned:
            self.restarts += 1
        return self.healthy()

    def suspend(self):
        return True
        try:
            if self.process is not None:
                self._wait_for_status(psutil.STATUS_SLEEPING)
                self.process.suspend()
                return self._wait_for_status(psutil.STATUS_STOPPED)
        except Exception:
            pass
        return False

    def resume(self):
        return True
        try:
            if self.process is not None:
                self.process.resume()
                return self._wait_for_status(psutil.STATUS_SLEEPING)
        except Exception:
            pass
        return False

    def _wait_for_status(self, status: str, timeout: float = 1.0, sleep_time: float = 0.0001, negate: bool = False) -> bool:
        if self.process is None:
            return False
        cumulative_t = 0.0
        try:
            if not negate:
                while self.process.status() is not status:
                    # we are literally waiting for the process to wait on its socket
                    if cumulative_t >= timeout:
                        return False
                    time.sleep(sleep_time)
                    cumulative_t += sleep_time
            else:
                while self.process.status() is status:
                    # we are literally waiting for the process to wait on its socket
                    if cumulative_t >= timeout:
                        return False
                    time.sleep(sleep_time)
                    cumulative_t += sleep_time
        except Exception:
            return False
        return True

    # def assert_healthy(self, force_kill=False) -> Tuple[bool, int]:
    #     while not self.healthy() or force_kill:
    #         self.kill()
    #         self.restart()
    #         force_kill = False
    #     ret = (False, 0) if self.retval is None else (True, self.retval)
    #     if self.retval is not None:
    #         self.crashes += 1
    #     self.retval = None
    #     return ret

    def kill(self, ignore=False):
        if self.process is None:
            return -1
        try:
            self._wait_for_status(status=psutil.STATUS_SLEEPING)
            retval = -1
            children = self.process.children()
            for child in children:
                child.terminate()
            _, alive = psutil.wait_procs(children, timeout=1.0)
            for bad_boy in alive:
                bad_boy.kill()
            if self.process.status() == psutil.STATUS_STOPPED:
                self.resume()
            self.process.terminate()
            _, alive = psutil.wait_procs([self.process], timeout=1.0)
            if len(alive) > 0:
                self.process.kill()
                psutil.wait_procs([self.process], timeout=1.0)
            if not ignore:
                retval = self.process.returncode
                self.crashes += 1
        except Exception:
            retval = 0
        self.process = None
        return retval

    def healthy(self) -> bool:
        try:
            # if self.process is not None:
            #     print(self.process.status())
            return self.process is not None and self.process.status() not in [psutil.STATUS_DEAD, psutil.STATUS_ZOMBIE]
        except Exception:
            return False

    def _fork(self, environ: {}) -> int:
        """
        Fork the target via execve

        :param environ: Dictionary representing the environment variables of the child process
        :return: child pid (int)
        """
        cid = subprocess.Popen(args=self._argv,
                               shell=False,
                               env=environ,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True,
                               close_fds=True).pid
        return cid


def _update_env(identifier: str) -> {}:
    """
    Copy and update parent environment by supplementing AFL instrumentation environment variable

    :param identifier: shared memory identifier
    :return: Updated copy of environment dict
    """
    environ = os.environ.copy()
    environ[INSTR_AFL_ENV] = str(identifier)
    return environ

