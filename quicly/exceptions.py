#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from enum import IntEnum

class QuicProtocolError(Exception):
    """Base class for all QUIC protocol-related exceptions."""
    pass

class QuicProtocolViolation(QuicProtocolError):
    """Raised when the peer violates the communication protocol (as defined by standard)."""
    pass

class QuicErrorCode(IntEnum):
    """These can be used with Python exceptions and also in the QUIC Frame TRANSPORT_CLOSE = 0x1c"""
    NO_ERROR = 0x0
    INTERNAL_ERROR = 0x1
    CONNECTION_REFUSED = 0x2
    FLOW_CONTROL_ERROR = 0x3
    STREAM_LIMIT_ERROR = 0x4
    STREAM_STATE_ERROR = 0x5
    FINAL_SIZE_ERROR = 0x6
    FRAME_ENCODING_ERROR = 0x7
    TRANSPORT_PARAMETER_ERROR = 0x8
    CONNECTION_ID_LIMIT_ERROR = 0x9
    PROTOCOL_VIOLATION = 0xA
    INVALID_TOKEN = 0xB
    APPLICATION_ERROR = 0xC
    CRYPTO_BUFFER_EXCEEDED = 0xD
    KEY_UPDATE_ERROR = 0xE
    AEAD_LIMIT_REACHED = 0xF
    CRYPTO_ERROR = 0x100

class QuicConnectionError(QuicProtocolError):
    def __init__(self, error_code: QuicErrorCode, reason_phrase: str):
        self.error_code = error_code
        self.reason_phrase = reason_phrase

# class QuicProtocolTimeout(QuicProtocolError):
#     """Raised when a peer times out."""
#     pass
