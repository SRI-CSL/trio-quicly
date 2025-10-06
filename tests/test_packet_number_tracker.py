
#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
#

import pytest
import random
import time

from quicly.frame import QuicFrameType
from quicly.acks import PacketNumberSpace, ack_to_intervals

NOW = time.time()

def test_tracker_merging_and_ack_building():
    tr = PacketNumberSpace()
    # receive 1,2,3 and 10,11,15
    for pn in [1,2,3,10,11,15]:
        tr.note_received(pn, NOW)

    # Intervals should be [(15,15), (10,11), (1,3)] descending by high
    # Build an ACK with at most 3 ranges (all of them)
    ack = tr.to_ack_frame(frame_type=QuicFrameType.ACK, now=NOW, max_ranges=3)
    ivs = ack_to_intervals(ack.content)
    assert ivs == [(15,15), (10,11), (1,3)]

def test_tracker_duplicate_and_adjacent_merge():
    tr = PacketNumberSpace()
    for pn in [5,7,6,6,8]:  # include duplicate 6 and out-of-order inserts
        tr.note_received(pn, NOW)
    # should merge to [5..8]
    ack = tr.to_ack_frame(frame_type=QuicFrameType.ACK, now=NOW)
    ivs = ack_to_intervals(ack.content)
    assert ivs == [(5,8)]

def test_tracker_drop_acked_up_to():
    tr = PacketNumberSpace()
    for pn in [1,2,3,10,11,20]:
        tr.note_received(pn, NOW)
    # drop everything <= 10 => remaining intervals should cover (11..11) and (20..20)
    tr.drop_acked_up_to(10)
    ack = tr.to_ack_frame(frame_type=QuicFrameType.ACK, now=NOW, max_ranges=2)
    ivs = ack_to_intervals(ack.content)
    assert ivs == [(20,20), (11,11)]

def test_max_ranges_cap_enforced():
    tr = PacketNumberSpace()
    # Create 6 disjoint singletons: 100, 90, 80, 70, 60, 50
    for pn in [100, 90, 80, 70, 60, 50]:
        tr.note_received(pn, NOW)
    # Request only top 3 ranges
    ack = tr.to_ack_frame(frame_type=QuicFrameType.ACK, now=NOW, max_ranges=3)
    ivs = ack_to_intervals(ack.content)
    assert len(ivs) == 3
    # Expect the three with highest highs: 100, 90, 80
    assert ivs == [(100,100), (90,90), (80,80)]

# Reference interval builder (independent oracle)
def ref_intervals_from_set(pns: set[int]):
    if not pns:
        return []
    nums = sorted(pns)
    # Build contiguous ranges [lo..hi]
    ranges = []
    start = prev = nums[0]
    for x in nums[1:]:
        if x == prev + 1:
            prev = x
            continue
        # close current
        ranges.append((start, prev))
        start = prev = x
    ranges.append((start, prev))
    # Sort by high descending (like tracker)
    ranges.sort(key=lambda r: r[1], reverse=True)
    return ranges

@pytest.mark.parametrize("seed", [0, 1, 2, 3, 4])
def test_randomized_tracker_matches_reference(seed):
    rng = random.Random(seed)
    tr = PacketNumberSpace()
    sent = set()
    # Generate 200 random packet numbers in [0, 2000)
    for _ in range(200):
        pn = rng.randrange(0, 2000)
        sent.add(pn)
        tr.note_received(pn, NOW)
    # Build ACK and compare intervals
    ack = tr.to_ack_frame(frame_type=QuicFrameType.ACK, now=NOW, max_ranges=None)
    got = ack_to_intervals(ack.content)
    expect = ref_intervals_from_set(sent)
    assert got == expect, f"Intervals mismatch for seed={seed}"
