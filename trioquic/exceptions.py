class QuicProtocolError(Exception):
    """Base class for all QUIC protocol-related exceptions."""
    pass

class QuicProtocolViolation(QuicProtocolError):
    """Raised when the peer violates the communication protocol (as defined by standard)."""
    pass

class QuicProtocolTimeout(QuicProtocolError):
    """Raised when a peer times out."""
    pass
