from typing import Generator
from .graph import Graph


class TransitionPayload(object):
    def __init__(self, name: str, payload: bytes = b'', recv_after_send: bool = False):
        self._n: str = name
        self._p: bytes = payload
        self._recv: bool = recv_after_send

    @property
    def name(self) -> str:
        return self._n

    @property
    def bytes(self) -> bytes:
        return self._p

    @property
    def recv_after_send(self) -> bool:
        return self._recv

    def __repr__(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.__repr__()


class TransitionGraph(Graph):
    def __init__(self, population: 'Population'):
        super().__init__()
        self._pre_done = False
        self._post_done = False
        self.pop = population
        self._prev_node = self.root
        self.has_pre_phase = False
        self.has_post_phase = False

    def pre(self, payload: TransitionPayload):
        if self._pre_done or self._post_done:
            raise ValueError("Pre-Phase has completed")
        self.connect(src=self._prev_node, dst=payload)
        self._prev_node = payload
        self.has_pre_phase = True

    def post(self, payload: TransitionPayload):
        if not self._pre_done or self._post_done:
            raise ValueError("Pre-Phase has to be completed and post-phase has still to be open")
        self.connect(src=self._prev_node, dst=payload)
        self._prev_node = payload
        self.has_post_phase = True

    def finalize_pre(self):
        if self._pre_done:
            raise ValueError("Pre-phase is already finished")
        self.connect(src=self._prev_node, dst=self.pop)
        self._prev_node = self.pop
        self._pre_done = True

    def finalize_post(self):
        if not self._pre_done or self._post_done:
            raise ValueError("Pre-Phase has to be completed and post-phase has still to be open")
        self._post_done = True

    def traverse_pre_phase(self) -> Generator[TransitionPayload, None, None]:
        if not self._pre_done or not self._post_done:
            raise ValueError("Graph has to be finalized first")
        if not self.has_pre_phase:
            return
        for pre in self.traverse_from_to(self.root, self.pop):
            if self.root == pre or self.pop == pre:
                continue
            yield pre

    def traverse_post_phase(self) -> Generator[TransitionPayload, None, None]:
        if not self._pre_done or not self._post_done:
            raise ValueError("Graph has to be finalized first")
        if not self.has_post_phase:
            return
        leaf = [x for x in self.g.nodes() if self.g.out_degree(x) == 0 and self.g.in_degree(x) == 1][0]
        for pre in self.traverse_from_to(self.pop, leaf):
            if self.pop == pre:
                continue
            yield pre
