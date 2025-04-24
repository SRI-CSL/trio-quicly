#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from dataclasses import dataclass

SMALLEST_MAX_DATAGRAM_SIZE = 1200

@dataclass
class QuicConfiguration:
    """
    A QUIC configuration.
    """

    ipv6: bool = False

    is_client: bool = True
    """
    Whether this is the client side of the QUIC connection.
    """

    max_data: int = 1048576
    """
    Connection-wide flow control limit.
    """

    max_datagram_size: int = SMALLEST_MAX_DATAGRAM_SIZE
    """
    The maximum QUIC payload size in bytes to send, excluding UDP or IP overhead.
    """