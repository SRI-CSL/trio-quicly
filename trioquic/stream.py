from typing import *

import trio.abc

from trioquic.connection import QuicConnection

# Stream Types
# 0x00 	Client-Initiated, Bidirectional
# 0x01 	Server-Initiated, Bidirectional
# 0x02 	Client-Initiated, Unidirectional
# 0x03 	Server-Initiated, Unidirectional



class QuicStream(trio.abc.AsyncResource):
    def __init__(
        self,
        connection: QuicConnection,
        stream_id: Optional[int] = None,
    ) -> None:
        self.connection = connection
        self.stream_id = stream_id
        self.is_closed = False
        self.first_send_or_receive = True

    async def aclose(self):
        if not self.is_closed:
            # TODO: any QUIC-related shutdown when canceling a Stream
            pass
        self.is_closed = True

@final
class QuicSendStream(trio.abc.SendStream, QuicStream):
    def __init__(
            self,
            connection: QuicConnection,
            stream_id: Optional[int] = None,
    ) -> None:
        super(QuicStream).__init__(connection, stream_id)

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        if self.first_send_or_receive:
            # TODO: initiate stream
            self.first_send = False
        # TODO: receive data...

@final
class QuicReceiveStream(trio.abc.ReceiveStream, QuicStream):
    def __init__(
            self,
            connection: QuicConnection,
            stream_id: Optional[int] = None,
    ) -> None:
        super(QuicStream).__init__(connection, stream_id)

    async def receive_some(self, max_bytes: int | None = None) -> bytes | bytearray:
        if self.first_send_or_receive:
            # TODO: initialize stream
            self.first_send = False
        # TODO: receive data...

@final
class QuicBidiStream(QuicSendStream, QuicReceiveStream):
    def __init__(
            self,
            connection: QuicConnection,
            stream_id: Optional[int] = None,
    ) -> None:
        super(QuicSendStream).__init__(connection, stream_id)
        super(QuicReceiveStream).__init__(connection, stream_id)
