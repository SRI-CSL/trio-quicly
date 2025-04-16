# TODO: add functions that help with coalescing QUIC packets into UDP datagram payloads and the inverse.
#  Possibly also help with multiple QUIC frames unless this must be done cryptographically

# From RFC 9000:
#
# Coalescing packets in order of increasing encryption levels (Initial, 0-RTT, Handshake, 1-RTT; see Section 4.1.4 of
# [QUIC-TLS]) makes it more likely that the receiver will be able to process all the packets in a single pass. A packet
# with a short header does not include a length, so it can only be the last packet included in a UDP datagram. An
# endpoint SHOULD include multiple frames in a single packet if they are to be sent at the same encryption level,
# instead of coalescing multiple packets at the same encryption level.
#
# Receivers MAY route based on the information in the first packet contained in a UDP datagram. Senders MUST NOT
# coalesce QUIC packets with different connection IDs into a single UDP datagram. Receivers SHOULD ignore any subsequent
# packets with a different Destination Connection ID than the first packet in the datagram.
#
# Every QUIC packet that is coalesced into a single UDP datagram is separate and complete. The receiver of coalesced
# QUIC packets MUST individually process each QUIC packet and separately acknowledge them, as if they were received as
# the payload of different UDP datagrams. For example, if decryption fails (because the keys are not available or for
# any other reason), the receiver MAY either discard or buffer the packet for later processing and MUST attempt to
# process the remaining packets.
#
# Retry packets (Section 17.2.5), Version Negotiation packets (Section 17.2.1), and packets with a short
# header (Section 17.3) do not contain a Length field and so cannot be followed by other packets in the same UDP
# datagram. Note also that there is no situation where a Retry or Version Negotiation packet is coalesced with
# another packet.
