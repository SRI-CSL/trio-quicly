# Primer on Acknowledgements in QUIC-LY

These notes are just a summary of the most pertaining parts of the RFC9000 (QUIC) standard and its adoption in QUIC-LY.

## Generating Acknowledgements

(see also RFC9000, Section 13.2)

### ACK-eliciting packets received

Every packet SHOULD be acknowledged at least once, and ack-eliciting packets MUST be acknowledged at least once 
within the maximum delay an endpoint communicated using the max_ack_delay transport parameter. An endpoint MUST 
acknowledge all ack-eliciting Initial packets immediately and all ack-eliciting 1-RTT packets within its advertised 
max_ack_delay.

In order to assist loss detection at the sender, an endpoint SHOULD generate and send an ACK frame without delay 
when it receives an ack-eliciting packet either:
  * when the received packet has a packet number less than another ack-eliciting packet that has been received, or
  * when the packet has a packet number larger than the highest-numbered ack-eliciting packet that has been received 
    and there are missing packets between that packet and this packet.

Similarly, packets marked with the ECN Congestion Experienced (CE) codepoint in the IP header SHOULD be acknowledged 
immediately, to reduce the peer's response time to congestion events.

A receiver SHOULD send an ACK frame after receiving at least two ack-eliciting packets. 

### Non-ACK-eliciting packets received

Non-ack-eliciting packets are eventually acknowledged when the endpoint sends an ACK frame in response to other events. 

## ACK Ranges

A receiver limits the number of ACK Ranges it remembers and sends in ACK frames, both to limit the size of ACK 
frames and to avoid resource exhaustion. After receiving acknowledgments for an ACK frame, the receiver SHOULD stop 
tracking those acknowledged ACK Ranges. Senders can expect acknowledgments for most packets, but QUIC does not 
guarantee receipt of an acknowledgment for every packet that the receiver processes.

A receiver MUST retain an ACK Range unless it can ensure that it will not subsequently accept packets with numbers 
in that range. Maintaining a minimum packet number that increases as ranges are discarded is one way to achieve this 
with minimal state. Receivers can discard all ACK Ranges, but they MUST retain the largest packet number that has 
been successfully processed, as that is used to recover packet numbers from subsequent packets per packet number 
decoding algorithm.

A receiver SHOULD include an ACK Range containing the largest received packet number in every ACK frame. 

### Limiting Ranges by Tracking ACK Frames

When a packet containing an ACK frame is sent, the Largest Acknowledged field in that frame can be saved. When a 
packet containing an ACK frame is acknowledged, the receiver can stop acknowledging packets less than or equal to 
the Largest Acknowledged field in the sent ACK frame.

A receiver that sends only non-ack-eliciting packets, such as ACK frames, might not receive an acknowledgment for a 
long period of time. This could cause the receiver to maintain state for a large number of ACK frames for a long 
period of time, and ACK frames it sends could be unnecessarily large. In such a case, a receiver could send a PING 
or other small ack-eliciting frame occasionally, such as once per round trip, to elicit an ACK from the peer.

In cases without ACK frame loss, this algorithm allows for a minimum of 1 RTT of reordering. In cases with ACK frame
loss and reordering, this approach does not guarantee that every acknowledgment is seen by the sender before it is 
no longer included in the ACK frame. Packets could be received out of order, and all subsequent ACK frames containing 
them could be lost. In this case, the loss recovery algorithm could cause spurious retransmissions, but the sender 
will continue making forward progress.

## Subtle Difference between QUIC and QUIC-LY

In RFC9000, Section 13.2.6, the standard states: "ACK frames MUST only be carried in a packet that has the same packet 
number space as the packet being acknowledged." This is because of the packet protection by encryption. In QUIC-LY, we 
don't have protection and only cleartext packets and frames. The Initial handshake is only used to establish the 
Connection IDs of client and server and agree on the transport parameters. Therefore, the ACK Frame produced in 
response to receiving the server's Initial packet at the client will be sent in a 1-RTT packet but acknowledges the 
packet number of the Initial space.

We propose to not distinguish Initial and 1-RTT phases and use consecutive packet numbers across both, meaning that the 
first 1-RTT packet number is at least one more of the packet number used in Initial.
