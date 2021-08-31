"""
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Mario Rivas, mario.rivas@nccgroup.com

http://www.github.com/nccgroup/EPF

Forked From BooFuzz and Sulley
https://github.com/jtpereyda/boofuzz

Licensed under GNU General Public License v2.0 - See LICENSE.txt
"""

from epf.helpers import deprecated
from . import exception
from .constants import BIG_ENDIAN, LITTLE_ENDIAN
from .connections import ITargetConnection
from .exception import EPFRuntimeError, SizerNotUtilizedError, MustImplementException
from .connections import SocketConnection
from .connections.target import Target
from .session import Session
from .responses import *
__version__ = '0.8.2'
