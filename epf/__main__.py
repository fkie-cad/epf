#!/usr/bin/python3
"""
Forked From BooFuzz, Sulley, and Fuzzowski
https://github.com/jtpereyda/boofuzz
http://www.github.com/nccgroup/fuzzowski

Licensed under GNU General Public License v2.0 - See LICENSE.txt
"""

import argparse
from numpy import random
import random as stdrandom

from . import Target, SocketConnection, constants
from .fuzzers import IFuzzer
from .restarters import IRestarter
from .session import Session

logo = """
`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"
   `=`,'=/     `=`,'=/     `=`,'=/     `=`,'=/
     y==/        y==/        y==/        y==/
   ,=,-<=`.    ,=,-<=`.    ,=,-<=`.    ,=,-<=`.
,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_
        - Evolutionary Protocol Fuzzer -
"""


class EPF(object):

    def __init__(self):
        self.session = None  # ok

        self._init_argparser()  # ok
        self.args = self._parse_args()  # ok

        self.target = Target(  # ok
            connection=SocketConnection(  # ok
                host=self.args.host,
                port=self.args.port,
                proto=self.args.protocol,
                send_timeout=self.args.send_timeout,
                recv_timeout=self.args.recv_timeout,
            )
        )

        self.session = Session(
            restart_sleep_time=self.args.restart_sleep_time,
            target=self.target,
            restarter=self.restart_module,
            fuzz_protocol=self.args.fuzz_protocol,
            seed=self.args.seed,
            time_budget=self.args.time_budget,
            alpha=self.args.alpha,
            beta=self.args.beta,
            population_limit=self.args.plimit,
            debug=self.args.debug,
            output=self.args.output,
            dump_shm=self.args.dump_shm,
            deterministic=False  # broken
        )

    # --------------------------------------------------------------- #

    def _init_argparser(self):
        """
        Initializes the argparser inside self.parser
        """

        self.parser = argparse.ArgumentParser(
            description=logo,
            formatter_class=argparse.RawTextHelpFormatter
        )

        self.parser.add_argument("host", help="target host")
        self.parser.add_argument("port", type=int, help="target port")
        conn_grp = self.parser.add_argument_group('Connection options')
        conn_grp.add_argument("-p", "--protocol", dest="protocol", help="transport protocol", default='tcp',
                              choices=['tcp', 'udp', 'tcp+tls'])
        conn_grp.add_argument("-st", "--send_timeout", dest="send_timeout", type=float, default=5.0,
                              help="send() timeout")
        conn_grp.add_argument("-rt", "--recv_timeout", dest="recv_timeout", type=float, default=5.0,
                              help="recv() timeout")

        fuzzers = [fuzzer_class.name for fuzzer_class in IFuzzer.__subclasses__()]

        fuzz_grp = self.parser.add_argument_group('Fuzzer options')
        fuzz_grp.add_argument("--fuzzer", dest="fuzz_protocol", help='application layer fuzzer', required=True,
                              choices=fuzzers)
        fuzz_grp.add_argument('--debug', action='store_true', help='enable debug.csv')
        fuzz_grp.add_argument('--batch', action='store_true', help='non-interactive, very quiet mode')
        fuzz_grp.add_argument('--dtrace', action='store_true', help='extremely verbose debug tracing')
        fuzz_grp.add_argument('--pcap', dest='pcap', type=str, required=True, help='pcap population seed')
        fuzz_grp.add_argument('--seed', dest='seed', type=int, default=0, help='prng seed')
        fuzz_grp.add_argument('--alpha', dest='alpha', type=float, default=0.995, help='simulated annealing cooldown parameter')
        fuzz_grp.add_argument('--beta', dest='beta', type=float, default=0.950, help='simulated annealing reheat parameter')
        fuzz_grp.add_argument('--smut', dest='smut', type=float, default=0.8, help='spot mutation probability')
        fuzz_grp.add_argument('--plimit', dest='plimit', type=int, default=10000, help='population limit')
        fuzz_grp.add_argument('--budget', dest='time_budget', type=float, default=0.0, help='time budget')
        fuzz_grp.add_argument('--output', dest='output', type=str, default="", help='output dir')
        fuzz_grp.add_argument('--shm_id', dest='shm_id', type=str, default="", help='custom shared memory id overwrite')
        fuzz_grp.add_argument('--dump_shm', dest='dump_shm', action='store_true', default=False, help='dump shm after run')
        #fuzz_grp.add_argument('--deterministic', dest='deterministic', action='store_true', default=False, help='SLOW mode, ~2x less iterations, but fairly deterministic runs (verify by comparing two --dtrace runs)')

        restarters_grp = self.parser.add_argument_group('Restart options')
        restarters_help = 'Restarter Modules:\n'
        for restarter in IRestarter.__subclasses__():
            restarters_help += '  {}: {}\n'.format(restarter.name(), restarter.help())
        restarters_grp.add_argument('--restart', nargs='+', default=[], metavar=('module_name', 'args'),
                                    help=restarters_help)
        restarters_grp.add_argument("--restart-sleep", dest="restart_sleep_time", type=int, default=5,
                                    help='Set sleep seconds after a crash before continue (Default 5)')

    def _parse_args(self) -> argparse.Namespace:
        """
        Parse arguments with argparse

        Returns:
            (argparse.Namespace) Argparse arguments
        """
        args = self.parser.parse_args()
        if args.dtrace:
            constants.TRACE = True
        constants.SPOT_MUT = args.smut
        if args.batch:
            constants.BATCH = True

        if args.shm_id != "":
            constants.SHM_OVERWRITE = args.shm_id

        random.seed(args.seed)
        stdrandom.seed(args.seed)
        args.fuzz_protocol = [icl for icl in IFuzzer.__subclasses__() if icl.name == args.fuzz_protocol][0]
        args.fuzz_protocol.initialize(**args.__dict__)

        self.restart_module = None
        if len(args.restart) > 0:
            try:
                restart_module = [mod for mod in IRestarter.__subclasses__() if mod.name() == args.restart[0]][0]
                restart_args = args.restart[1:]
                self.restart_module = restart_module(*restart_args)
            except IndexError:
                print(f"The restarter module {args.restart[0]} does not exist!")
                exit(1)

        return args

    def run(self):
        """Start the session fuzzer!"""
        self.session.start()


def main():
    epf = EPF()
    print(logo)
    epf.run()


if __name__ == '__main__':
    main()
