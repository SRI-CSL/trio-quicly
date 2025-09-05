from quicly.acks import iter_ack_frames, ack_to_intervals
from quicly.frame import QuicFrameType, QuicFrame, ACKFrame, ACKRange, ECNCounts


def make_ack(largest, first_len, pairs):
    """
    Helper to build an ACKFrame with given ranges.
    pairs: list of (gap, length) for subsequent ranges
    """
    return ACKFrame(
        largest_ack=largest,
        ack_delay=1000,  # 1ms in us
        first_ack_range=first_len,
        ack_ranges=[ACKRange(gap=g, ack_range_length=l) for (g,l) in pairs],
        ecn_counts=None,
    )

def test_ack_to_intervals_single_range():
    # ACK { largest=10, first_len=3 } => [7..10]
    ack = make_ack(10, 3, [])
    ivs = ack_to_intervals(ack)
    assert ivs == [(7, 10)]

def test_ack_to_intervals_multiple_ranges():
    # RFC-style example: largest=100, first_len=5 => [95..100]
    # next: gap=2 => skip 2 between 94 and next_high => next_high = 94 - 1 - 2 = 91
    #      len=3 => [88..91]
    # next: gap=0 => next_high = 88 - 1 - 0 = 87 ; len=1 => [86..87]
    ack = make_ack(100, 5, [(2, 3), (0, 1)])
    ivs = ack_to_intervals(ack)
    assert ivs == [(95, 100), (88, 91), (85, 86)]

def test_iter_ack_frames_filters_correctly():
    a = make_ack(9, 0, [])
    qf_ack = QuicFrame(QuicFrameType.ACK, a)
    qf_ack_ecn = QuicFrame(QuicFrameType.ACK_ECN, make_ack(5, 0, []))
    qf_pad = QuicFrame(QuicFrameType.PADDING, None)

    got = list(iter_ack_frames([qf_pad, qf_ack, qf_ack_ecn]))
    assert len(got) == 2
    assert isinstance(got[0], ACKFrame) and isinstance(got[1], ACKFrame)
    assert got[0].largest_ack == 9
    assert got[1].largest_ack == 5

def test_iter_ack_frames_includes_ack_ecn_and_intervals_work():
    # ACK_ECN with one range [40..45], plus ECN counts
    ack = ACKFrame(
        largest_ack=45,
        ack_delay=2000,
        first_ack_range=5,
        ack_ranges=[],
        ecn_counts=ECNCounts(ect0=10, ect1=5, ce=2)
    )
    qf = QuicFrame(QuicFrameType.ACK_ECN, ack)

    lst = list(iter_ack_frames([qf]))
    assert len(lst) == 1 and lst[0].ecn_counts is not None
    ivs = ack_to_intervals(lst[0])
    assert ivs == [(40,45)]
