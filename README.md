# EPF - Evolutionary Protocol Fuzzer

<div style="text-align: center;">
<img src="https://i.ibb.co/mRnRfc4/sys-overview.png" alt="system overview" style="width:100%;"/>
</div>

**EPF** is a coverage guided protocol-aware network fuzzer.
It combines [Scapy](https://github.com/secdev/scapy) packet models with
prebuilt state transition graphs to increase process depth and, 
[thus](https://mboehme.github.io/paper/IEEESoftware20.pdf), bug finding
effectiveness during dynamic analysis.
Static instrumentation - borrowed from
[AFL](https://lcamtuf.coredump.cx/afl/) and
[AFL++](https://github.com/AFLplusplus/AFLplusplus)
([USENIX](https://www.usenix.org/conference/woot20/presentation/fioraldi)) -
is used to establish a dynamic feedback loop that is fed into a
population-based simulated annealing algorithm.
The fuzzer aims to maximize test coverage metrics on the target
by incrementally evolving and mutating a population of valid sample packets.
Such *seeds* are obtained by feeding EPF with PCAP files.

In other words, you teach EPF a target protocol, pass a compile-time instrumented
target network binary, and provide PCAP examples of well-defined communication.
EPF then tries to maximize fuzzing effectiveness by automatically setting the
network target into reasonable processing states. Genetic algorithms derive new -
partially corrupt - packets with the goal to trigger undefined behavior and security
policy violations during dynamic analysis.

***Disclaimer: This repository serves academic code.***

## Contents

1. [**About**](#about)
2. [**Dependencies**](#dependencies)
3. [**Setup**](#setup)
4. [**Synopsis**](#synopsis)
5. [**Example**](#example)
6. [**Contributions**](#contributions)

## About

Coming soon :wink:

## Dependencies

**System:**

```bash
sudo apt-get update && sudo apt get install python3 python3-pip python3-venv
```

*Additionally:* [AFL++](https://github.com/AFLplusplus/AFLplusplus) for compile-time instrumentation.

**Python:**

```plain
prompt-toolkit
attrs
pygments
pydot
sysv_ipc
posix_ipc
networkx
scapy
matplotlib
npyscreen
hexdump
numpy
psutil
cryptography
```

## Setup

1. install [AFL++](https://github.com/AFLplusplus/AFLplusplus) by following the
project's [build instructions](https://github.com/AFLplusplus/AFLplusplus#building-and-installing-afl).
2. install EPF:
```bash
git clone https://github.com/rhelmke/epf.git # clone
cd epf                                       # workdir
python3 -m venv .env                         # setup venv
source .env/bin/activate                     # activate venv
pip3 install -r requirements.txt             # dependencies
```

You should now have a working copy of both AFL++ and EPF. Verify the latter with:
```bash
python3 -m epf --help
```
EPF must always be executed within the previously setup virtual python environment.

## Synopsis

```plain
$ python3 -m epf --help

`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"
   `=`,'=/     `=`,'=/     `=`,'=/     `=`,'=/
     y==/        y==/        y==/        y==/
   ,=,-<=`.    ,=,-<=`.    ,=,-<=`.    ,=,-<=`.
,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_
        - Evolutionary Protocol Fuzzer -

positional arguments:
  host                  target host
  port                  target port

optional arguments:
  -h, --help            show this help message and exit

Connection options:
  -p {tcp,udp,tcp+tls}, --protocol {tcp,udp,tcp+tls}
                        transport protocol
  -st SEND_TIMEOUT, --send_timeout SEND_TIMEOUT
                        send() timeout
  -rt RECV_TIMEOUT, --recv_timeout RECV_TIMEOUT
                        recv() timeout

Fuzzer options:
  --fuzzer {iec104}     application layer fuzzer
  --debug               enable debug.csv
  --batch               non-interactive, very quiet mode
  --dtrace              extremely verbose debug tracing
  --pcap PCAP           pcap population seed
  --seed SEED           prng seed
  --alpha ALPHA         simulated annealing cooldown parameter
  --beta BETA           simulated annealing reheat parameter
  --smut SMUT           spot mutation probability
  --plimit PLIMIT       population limit
  --budget TIME_BUDGET  time budget
  --output OUTPUT       output dir
  --shm_id SHM_ID       custom shared memory id overwrite
  --dump_shm            dump shm after run

Restart options:
  --restart module_name [args ...]
    Restarter Modules:
        afl_fork: '<executable> [<argument> ...]' (Pass command and arguments within quotes, as only one argument)
  --restart-sleep RESTART_SLEEP_TIME
                        Set sleep seconds after a crash before continue (Default 5)
```

## Example

To provide a working example on how to prepare and use EPF with your target protocol,
we are going to fuzz [lib60870](https://github.com/mz-automation/lib60870) by
MZ Automation. It is an open source implementation of the IEC 60870-5-101/104
SCADA protocols. They are commonly used in european critical power infrastructure
for remote monitoring and controlling.
The main reason of why this target has been chosen is of simple nature: the master's
thesis that EPF originates from focuses on this domain.

### Example Step 1: Download, Instrument, and Build the Target

*We assume that epf, aflplusplus, and lib60870 are all situated in the user's home.*

**Download**

```bash
git clone https://github.com/mz-automation/lib60870.git
cd lib60870/lib60870-C
```

**Prepare Instrumentation**

We need to exchange the C compiler with the AFL++ toolchain to instrument the code during
compilation. It is nothing but a wrapper for `clang`:

```bash
# may vary, check how your target project selects the compiler. most of the time, a CC=... environment variable is sufficient
echo "CC=~/AFLplusplus/afl-clang-fast" >> make/target_system.mk
```

**Compile**

```bash
make
```

You have now a working, instrumented, and statically linked library of
lib60870 that is compatible with both EPF and AFL++ (`./build/lib60870.a`).

**Test Harness**

You can not run lib60870 on its own because it is a library. This is why we need a
**test harness**, a minimal executable wrapper around the library that allows the
fuzzer to pass input to the target. In this case, we only need a wrapper that
initializes the library and creates a socket. The `cs104_server_no_threads` example
in the target's project folder
(`lib60870-C/examples/cs104_server_no_threads/cs104_server_no_threads.c`) is sufficient.
It is a minimal IEC 60870-5-104 slave server application.

Because the `Makefile` in this folder does adhere to `make/target_system.mk`,
we can simply compile the executable:

```bash
cd examples/cs104_server_no_threads
make
cp cs104_server_no_threads ~
```

The resulting `cs104_server_no_threads` executable is the input for EPF. Take note that
it has been copied to `~`.

### Step 2: Teach EPF the protocol

*Everything but the last paragraph is skippable if you only want to execute this example*

Each target protocol requires its own module in EPF's project structure.
Modules come in this subfolder:

```bash
cd ~/epf/epf/fuzzers
```

Take `iec104` as an example:

```python
$ cat iec104/iec104.py

from typing import Union, Dict

from epf.fuzzers.ifuzzer import IFuzzer
from epf import Session, constants
from epf.transition_payload import TransitionPayload
from epf.chromo import Population, Crossover
from scapy.contrib.scada.iec104 import IEC104_APDU_CLASSES
from scapy.packet import Packet


class IEC104(IFuzzer):
    name = 'iec104'
    pcap_file = ''
    populations = {}

    @staticmethod
    def layer_filter(pkt: Packet) -> Union[Packet, None]:
        """
        Filter to extract iec 104 apdu packets only.
        @param pkt: Packet to strip a specific layer from
        @return: Stripped Layer or None if completely discard
        """
        if not any(layer in pkt for layer in IEC104_APDU_CLASSES.values()):
            return None
        return pkt.getlayer(3)

    @staticmethod
    def get_populations(session: Session) -> Dict[str, Population]:
        return IEC104.populations

    # --------------------------------------------------------------- #

    @staticmethod
    def initialize(*args, **kwargs) -> None:
        IEC104.pcap_file = kwargs['pcap']
        IEC104.populations = Population.generate(
            pcap_filename=IEC104.pcap_file,
            layer_filter=IEC104.layer_filter,
            population_crossover_operator=Crossover.single_point,
            population_mutation_probability=constants.SPOT_MUT,
        )
        testfr = TransitionPayload(name="testfr", payload=b'\x68\x04\x43\x00\x00\x00', recv_after_send=True)#True)
        startdt = TransitionPayload(name="startdt", payload=b'\x68\x04\x07\x00\x00\x00', recv_after_send=True)#True)
        stopdt = TransitionPayload(name="stopdt", payload=b'\x68\x04\x13\x00\x00\x00', recv_after_send=False)
        # <-- in case we want to receive after sending an individual of a specific population
        for species, pop in IEC104.populations.items():
            if species == 'population_that_requires_receive':
                pop.recv_after_send = True
            if species != 'IEC-104 U APDU':
                pop.state_graph.pre(testfr)
                pop.state_graph.pre(startdt)
                pop.state_graph.finalize_pre()
                pop.state_graph.post(stopdt)
                pop.state_graph.finalize_post()
            else:
                pop.state_graph.finalize_pre()
                pop.state_graph.finalize_post()
```

Each protocol in EPF requires a layer filter, which uses scapy data models to filter
the relevant packets from PCAP files for dynamic analysis (`layer_filter(...)`).
Because iec104 is already supported by PCAP, we do not have to implement the models.

The `initialize` method is called by the fuzzer to kick off pcap parsing. Another
important aspect is the minimal state graph that is constructed for the purpose of
fuzzing IEC 60870-5-104.
You can define so-called `TransitionPayload(s)` which can be concatenated in a
directed acyclic graph. These are sent before (`pre`) fuzzing a specific packet type and
afterward (`post`). This enables EPF to connect to the target, open a session, and trigger
state transitions for proper packet handling. The code depicted above constructs
the following acyclic graph for the protocol-specific I- S-, and U-Packet Types:

<div style="text-align: center;">
<img src="https://i.ibb.co/m9jVcdw/state.png" alt="iec104 state graph" style="width:100%;"/>
</div>

That's it. If you follow this layout based on the iec104 module as example for your
own protocol, you are now done.

**Except for one small thing**: For our IEC 60870-5-104 example, we must apply a
data type patch to scapy's iec104 implementation because there is (in my opinion)
a bug in the sequence number field representation. Apply
the `01_scapy_iec104_sequence_number_fix.patch` which has been shipped as part
of the EPF project. It is in `~/epf/patches`.

### Example Step 3: Fuzz the target!

**Acquire a pcap file containing legitimate communication between the target and a
client**

... [here](https://github.com/automayt/ICS-pcap/raw/master/IEC%2060870/iec104/iec104.pcap)'s one for IEC 60870-5-104, for example. We call it `iec104.pcap` from now on.
You put it in `~/epf`.

**Run epf!**

... but don't forget to `cp ~/cs104_server_no_threads ~/epf` into EPF's project dir ;).

```bash
cd ~/epf
source .env/bin/activate  # activate virtualenv
python -m epf 127.0.0.1 2404 -p tcp --fuzzer iec104 --pcap iec104.pcap --seed 123456 --restart afl_fork "./cs104_server_no_threads" --smut 0.2 --plimit 1000 --alpha 0.99999333 --beta 1.0 --budget 86400
```

*Hint: Refer to [**Synopsis**](#synopsis) for the meaning of each argument.*

You'll be greeted with an interactive console, which is a stripped down version
of EPF's base project, [Fuzzowski](https://github.com/nccgroup/fuzzowski):

<div style="text-align: center;">
<img src="https://i.ibb.co/yPjMr5G/1fvx50G.png" alt="console" style="width:100%;"/>
</div>

Type `continue` to start fuzzing. This is the status screen:


<div style="text-align: center;">
<img src="https://i.ibb.co/264Mb1H/fLfssJY.png" alt="status" style="width:100%;"/>
</div>

Press `ctrl+q` to return to the console. Type `exit` to exit EPF.

Results are in `~/epf/epf-results`. However, they require manual verification
due to a high false positive rate: A bug that was introduced during the thesis
had to be hotfixed by flushing the history of previous

## Contributions

I'm actively looking for people that are willing to contribute their fuzzing- and
development-expertise to this project. The goal is to completely rewrite EPF's PoC
implementation in a more stable/structured/robust/effective/modular way.
The language of choice is Rust.
