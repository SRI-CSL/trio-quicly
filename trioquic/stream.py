from enum import IntEnum
from typing import *

import trio.abc

# Stream Types
# 0x00 	Client-Initiated, Bidirectional
# 0x01 	Server-Initiated, Bidirectional
# 0x02 	Client-Initiated, Unidirectional
# 0x03 	Server-Initiated, Unidirectional

class StreamType(IntEnum):
    CLIENT_BIDI = 0x00
    SERVER_BIDI = 0x01
    CLIENT_UNI = 0x02
    SERVER_UNI = 0x03

class QuicStream(trio.abc.AsyncResource):
    def __init__(
        self,
        stream_id: Optional[int] = None,
    ) -> None:
        self.stream_id = stream_id
        self.is_closed = False
        self.first_send_or_receive = True

    async def aclose(self):
        if not self.is_closed:
            # TODO: any QUIC-related shutdown when canceling a Stream
            pass
        self.is_closed = True

class QuicSendStream(trio.abc.SendStream, QuicStream):
    def __init__(
            self,
            stream_id: Optional[int] = None,
    ) -> None:
        super(QuicStream).__init__(stream_id)

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        if self.first_send_or_receive:
            # TODO: initiate stream
            self.first_send = False
        # TODO: receive data...

class QuicReceiveStream(trio.abc.ReceiveStream, QuicStream):
    def __init__(
            self,
            stream_id: Optional[int] = None,
    ) -> None:
        super(QuicStream).__init__(stream_id)

    async def receive_some(self, max_bytes: int | None = None) -> bytes | bytearray:
        if self.first_send_or_receive:
            # TODO: initialize stream
            self.first_send = False
        # TODO: receive data...

@final
class QuicBidiStream(QuicSendStream, QuicReceiveStream):
    def __init__(
            self,
            stream_id: Optional[int] = None,
    ) -> None:
        super(QuicSendStream).__init__(stream_id)
        super(QuicReceiveStream).__init__(stream_id)

    async def wait_send_all_might_not_block(self) -> None:
        pass
