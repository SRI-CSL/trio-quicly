
# Flexible imports: support flat or packaged layouts
try:
    from acks import PacketNumberTracker, ack_to_intervals
    from frame import ACKFrame, QuicFrame, ACKRange, QuicFrameType, ECNCounts
except Exception:
    from quicly.acks import PacketNumberTracker, ack_to_intervals  # type: ignore
    from quicly.frame import ACKFrame, QuicFrame, ACKRange, QuicFrameType, ECNCounts  # type: ignore

def _intervals_from_set(pns: set[int]):
    if not pns:
        return []
    nums = sorted(pns)
    ranges = []
    start = prev = nums[0]
    for x in nums[1:]:
        if x == prev + 1:
            prev = x
            continue
        ranges.append((start, prev))
        start = prev = x
    ranges.append((start, prev))
    ranges.sort(key=lambda r: r[1], reverse=True)
    return ranges

def test_ack_roundtrip_encode_decode_simple():
    sent = {1,2,3, 10,11, 20}
    expect = _intervals_from_set(sent)

    tr = PacketNumberTracker()
    for pn in sent:
        tr.note_received(pn)

    # Returns a QuicFrame wrapper
    qf = tr.to_ack_frame(QuicFrameType.ACK, ack_delay_us=1000)

    # Full on-wire (type+payload)
    wire = qf.encode()

    # Decode wrapper first
    qf2, used = QuicFrame.decode(wire)
    assert used == len(wire)
    assert qf2.frame_type == QuicFrameType.ACK
    ack2 = qf2.content
    got = ack_to_intervals(ack2)
    assert got == expect

def test_ack_ecn_roundtrip_manual():
    # [40..45] + ECN counts
    ack = ACKFrame(
        largest_ack=45,
        ack_delay=2000,
        first_ack_range=5,
        ack_ranges=[],
        ecn_counts=ECNCounts(ect0=10, ect1=5, ce=2),
    )
    # Payload only
    payload = ack.encode()
    ack2, used = ACKFrame.decode(payload, frame_type=QuicFrameType.ACK_ECN)
    assert used == len(payload)
    assert ack2.ecn_counts is not None
    assert (ack2.ecn_counts.ect0, ack2.ecn_counts.ect1, ack2.ecn_counts.ce) == (10,5,2)
    assert ack_to_intervals(ack2) == [(40,45)]
