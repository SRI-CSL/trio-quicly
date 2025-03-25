import trio
from typing import *

AddressFormat: TypeAlias = tuple[str, int]
PosArgsT = TypeVarTuple("PosArgsT")
_T = TypeVar("_T")

class _Queue(Generic[_T]):
    def __init__(self, incoming_packets_buffer: int | float) -> None:  # noqa: PYI041
        self.s, self.r = trio.open_memory_channel[_T](incoming_packets_buffer)

