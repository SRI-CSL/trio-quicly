
from quicly.acks import PacketNumberSpace
from quicly.recovery import QuicPacketRecovery
from quicly.utils import K_MILLI_SECOND


def test_recovery_contextvar_default_is_25ms():
    recovery = QuicPacketRecovery(False, PacketNumberSpace())
    # Expected default: 25 ms in seconds
    assert recovery._get_peer_max_ack_delay() == 25 * K_MILLI_SECOND


def test_recovery_contextvar_set_to_other_value_and_reset_to_default():
    recovery = QuicPacketRecovery(False, PacketNumberSpace())
    # 1) Set to a different value (e.g., 150 ms)
    QuicPacketRecovery.set_peer_max_ack_delay(150)
    assert recovery._get_peer_max_ack_delay() == 150 * K_MILLI_SECOND

    # 2) Set to None -> should reset to prior (150 ms)
    QuicPacketRecovery.set_peer_max_ack_delay(None)
    assert recovery._get_peer_max_ack_delay() == 150 * K_MILLI_SECOND
