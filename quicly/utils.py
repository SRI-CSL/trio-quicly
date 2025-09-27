#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
import binascii
import trio
from typing import *

K_MICRO_SECOND = 0.000001
K_MILLI_SECOND = 0.001
K_GRANULARITY  = 0.001    # 1 ms

AddressFormat: TypeAlias = tuple[str, int]
PosArgsT = TypeVarTuple("PosArgsT")
_T = TypeVar("_T")

class _Queue(Generic[_T]):
    def __init__(self, buffer_capacity: int | float) -> None:  # noqa: PYI041
        self.s, self.r = trio.open_memory_channel[_T](buffer_capacity)

def hexdump(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")
