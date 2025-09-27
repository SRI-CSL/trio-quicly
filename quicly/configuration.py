#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from dataclasses import dataclass, field
from enum import IntEnum
from typing import *

SMALLEST_MAX_DATAGRAM_SIZE = 1200

# === QUIC-LY Transport Parameters (CONFIG / CONFIG-ACK) =====================
# TODO: Linda: make sure that overriding max_datagram_frame_size > 0 needs to be also > MAX_UDP_PAYLOAD_SIZE!
#  For most uses of DATAGRAM frames,
#  it is RECOMMENDED to send a value of 65535 in the max_datagram_frame_size transport parameter to indicate that
#  this endpoint will accept any DATAGRAM frame that fits inside a QUIC packet.

class TransportParameterType(IntEnum):
    INITIAL_MAX_DATA             = 0x01  # bytes
    INITIAL_MAX_STREAM_DATA_BIDI = 0x02  # bytes
    INITIAL_MAX_STREAMS_BIDI     = 0x03  # count
    MAX_UDP_PAYLOAD_SIZE         = 0x04  # bytes
    IDLE_TIMEOUT_MS              = 0x05  # ms
    ACK_DELAY_EXPONENT           = 0x06  # —
    MAX_ACK_DELAY_MS             = 0x07  # ms
    DISABLE_ACTIVE_MIGRATION     = 0x08  # flag (VALUE_LEN=0 => true)
    INITIAL_PADDING_TARGET       = 0x09  # bytes
    MAX_DATAGRAM_FRAME_SIZE      = 0x20  # bytes

    def __str__(self):
        return self.name.lower()

PARAM_SCHEMA: dict[TransportParameterType, tuple[str, Callable[[int|bool], int|bool]]] = {
    TransportParameterType.INITIAL_MAX_DATA:             ("initial_max_data", int),
    TransportParameterType.INITIAL_MAX_STREAM_DATA_BIDI: ("initial_max_stream_data_bidi", int),
    TransportParameterType.INITIAL_MAX_STREAMS_BIDI:     ("initial_max_streams_bidi", int),
    TransportParameterType.MAX_UDP_PAYLOAD_SIZE:         ("max_udp_payload_size", int),
    TransportParameterType.IDLE_TIMEOUT_MS:              ("idle_timeout_ms", int),
    TransportParameterType.ACK_DELAY_EXPONENT:           ("ack_delay_exponent", int),
    TransportParameterType.MAX_ACK_DELAY_MS:             ("max_ack_delay_ms", int),
    TransportParameterType.DISABLE_ACTIVE_MIGRATION:     ("disable_active_migration", lambda v: bool(v)),
    TransportParameterType.INITIAL_PADDING_TARGET:       ("initial_padding_target", int),
    TransportParameterType.MAX_DATAGRAM_FRAME_SIZE:      ("max_datagram_frame_size", int),
}

# Defaults per QUIC-LY spec (recommended when CONFIG/CONFIG-ACK empty)
QUICLY_DEFAULTS: Dict[TransportParameterType, int | bool] = {
    TransportParameterType.INITIAL_MAX_DATA:             1_048_576,
    TransportParameterType.INITIAL_MAX_STREAM_DATA_BIDI:   262_144,
    TransportParameterType.INITIAL_MAX_STREAMS_BIDI:             8,
    TransportParameterType.MAX_UDP_PAYLOAD_SIZE:              1350,
    TransportParameterType.IDLE_TIMEOUT_MS:                  30000,
    TransportParameterType.ACK_DELAY_EXPONENT:                   3,
    TransportParameterType.MAX_ACK_DELAY_MS:                    25,
    TransportParameterType.DISABLE_ACTIVE_MIGRATION:         False,
    TransportParameterType.INITIAL_PADDING_TARGET:            1200,
    TransportParameterType.MAX_DATAGRAM_FRAME_SIZE:              0,
}

@dataclass
class QuicLyTransportParameters:
    """Strongly-typed view over transport params with QUIC-LY defaults."""
    initial_max_data: int             = QUICLY_DEFAULTS[TransportParameterType.INITIAL_MAX_DATA]             # bytes
    initial_max_stream_data_bidi: int = QUICLY_DEFAULTS[TransportParameterType.INITIAL_MAX_STREAM_DATA_BIDI] # bytes
    initial_max_streams_bidi: int     = QUICLY_DEFAULTS[TransportParameterType.INITIAL_MAX_STREAMS_BIDI]     # count
    max_udp_payload_size: int         = QUICLY_DEFAULTS[TransportParameterType.MAX_UDP_PAYLOAD_SIZE]         # bytes
    idle_timeout_ms: int              = QUICLY_DEFAULTS[TransportParameterType.IDLE_TIMEOUT_MS]              # ms
    ack_delay_exponent: int           = QUICLY_DEFAULTS[TransportParameterType.ACK_DELAY_EXPONENT]
    max_ack_delay_ms: int             = QUICLY_DEFAULTS[TransportParameterType.MAX_ACK_DELAY_MS]             # ms
    disable_active_migration: bool    = QUICLY_DEFAULTS[TransportParameterType.DISABLE_ACTIVE_MIGRATION]     # flag
    initial_padding_target: int       = QUICLY_DEFAULTS[TransportParameterType.INITIAL_PADDING_TARGET]       # bytes
    max_datagram_frame_size: int      = QUICLY_DEFAULTS[TransportParameterType.MAX_DATAGRAM_FRAME_SIZE]      # bytes

    def as_dict(self, include_defaults: bool = False) -> dict[str, int|bool]:
        return {f: getattr(self, f) for pid, (f, _) in PARAM_SCHEMA.items()
                if include_defaults or QUICLY_DEFAULTS[pid] != getattr(self, f)}

    def as_list(self, exclude_defaults: bool = False) -> list[tuple[int, int|bool]]:
        """
        Create a list view of transport parameters. If `exclude_defaults` is `True`, only those parameters different
        from defaults are included.
        :param exclude_defaults: Whether to exclude parameters with default values or not.
        :return: list of tuples of transport parameter names and their current values.
        """
        return [(pid, getattr(self, f)) for pid, (f, _) in PARAM_SCHEMA.items()
                if not exclude_defaults or QUICLY_DEFAULTS[pid] != getattr(self, f)]

    def update(self, new_params: Mapping[Union[str, "TransportParameterType"], int | bool]) -> bool:
        """
        Update the QUIC-LY transport parameters in place.
        :param new_params: Dictionary of transport parameter names and their new values.
        :return: True iff at least one value changed.
        """
        if new_params is None:
            return False
        changed = False
        for key, raw in new_params.items():
            # Allow enum keys or field-name strings
            name = str.lower(key.name) if hasattr(key, "name") else str(key)

            if not hasattr(self, name):
                continue  # ignore unknown keys

            current = getattr(self, name)
            # Normalize the incoming value to the attribute's type
            if isinstance(current, bool):
                new_val = bool(raw)
            elif isinstance(current, int):
                # Accept ints (and, if given, cast bools to ints explicitly)
                new_val = int(raw)
            else:
                # Fallback (shouldn't happen for this dataclass)
                new_val = raw

            if current != new_val:
                setattr(self, name, new_val)
                changed = True
        return changed


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

    transport_parameters: QuicLyTransportParameters = field(default_factory=QuicLyTransportParameters)
    """
    QUIC-LY default transport parameters.
    """

    max_ack_intervals: int = 10
    """
    The maximum number of ACK intervals to retain after sending an ACK Frame.
    """

def update_config(config: QuicConfiguration,
                  transport_parameters: dict[TransportParameterType | str | int, int | bool]):
    tps = config.transport_parameters
    if tps.update(transport_parameters):
        config.transport_parameters = tps
