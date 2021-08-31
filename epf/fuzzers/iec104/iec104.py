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

