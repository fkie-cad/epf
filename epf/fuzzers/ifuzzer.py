import abc
from typing import Dict

from epf import Session
from epf.chromo import Population


class IFuzzer(object):
    """Describes a fuzzer interface.
    """

    name = 'Implement'
    populations = []

    @staticmethod
    @abc.abstractmethod
    def get_populations(session: Session) -> Dict[str, Population]:
        """Get possible requests"""
        raise NotImplementedError("Subclasses should implement this!")

    @staticmethod
    @abc.abstractmethod
    def initialize(*args, **kwargs) -> None:
        """Get possible requests"""
        raise NotImplementedError("Subclasses should implement this!")
