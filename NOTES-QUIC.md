# Some Notes on QUIC Definitions and Nomenclature

Ack-eliciting Packet
: A QUIC Packet that contains frames other than ACK, PADDING, and CONNECTION_CLOSE. These cause a recipient to send an 
acknowledgment (potentially bundled with ack's for non-ack-eliciting packets).

Address
: When used without qualification, the tuple of IP version, IP address, and UDP port number that represents one end of 
a network path.

Application
: An entity that uses QUIC to send and receive data.

Client
: The endpoint that initiates a QUIC connection.

Connection
: A QUIC Connection is shared state between a client and a server. Connection IDs allow Connections to migrate to a new 
network path, both as a direct choice of an endpoint and when forced by a change in a middlebox.

Connection ID
: An identifier that is used to identify a QUIC connection at an endpoint. Each endpoint selects one or more Connection 
IDs for its peer to include in packets sent towards the endpoint. This value is opaque to the peer.

Endpoint
: An entity that can participate in a QUIC connection by generating, receiving, and processing QUIC packets. There are 
only two types of endpoints in QUIC: client and server.

Frame
: The payload of QUIC Packets, after removing packet protection, consists of a sequence of complete frames. Some Packet 
types (Version Negotiation, Stateless Reset, and Retry) do not contain Frames.

QUIC Packet
: QUIC Endpoints communicate by exchanging Packets. Packets have confidentiality and integrity protection. QUIC Packets
are complete processable units of QUIC that can be encapsulated in a UDP datagram. One or more QUIC Packets can be 
encapsulated in a single UDP datagram, which is in turn encapsulated in an IP packet.

Server
: The endpoint that accepts a QUIC connection.

Stream
:  A unidirectional or bidirectional channel of ordered bytes within a QUIC Connection. A QUIC Connection can carry 
multiple simultaneous streams. Streams can be created by either Endpoint, can concurrently send data interleaved with 
other Streams, and can be canceled. A unidirectional Stream allows only the Endpoint that initiated the stream to send 
data to its peer. Streams are identified within a Connection by a numeric value (62-bit integer), the Stream ID. The two 
least significant bits of the stream ID determine whether Client or Server created the Stream, and if the Stream is 
uni- or bidirectional.

## QUIC Transmission Machinery (see RFC9002)

Ack-eliciting frames
: All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting.

Ack-eliciting packets
: Packets that contain ack-eliciting frames elicit an ACK from the receiver within the maximum acknowledgment delay and 
are called ack-eliciting packets.

In-flight packets
: Packets are considered in flight when they are ack-eliciting or contain a PADDING frame, and they have been sent but 
are not acknowledged, declared lost, or discarded along with old keys.

The types of frames contained in a packet affect recovery and congestion control logic:
* All packets are acknowledged, though packets that contain no ack-eliciting frames are only acknowledged along with 
  ack-eliciting packets. 
* Long header packets that contain CRYPTO frames are critical to the performance of the QUIC handshake and use shorter 
  timers for acknowledgment.
* Packets containing frames besides ACK or CONNECTION_CLOSE frames count toward congestion control limits and are 
  considered to be in flight.
* PADDING frames cause packets to contribute toward bytes in flight without directly causing an acknowledgment to be 
  sent.

### QUIC Transmission and Delivery Order

QUIC separates transmission order from delivery order: packet numbers indicate transmission order, and delivery order 
is determined by the stream offsets in STREAM frames.

QUIC's packet number is strictly increasing within a packet number space and directly encodes transmission order. When 
a packet containing ack-eliciting frames is detected lost, QUIC includes necessary frames in a new packet with a new 
packet number, removing ambiguity about which packet is acknowledged when an ACK is received. 

### Estimating the Round-Trip-Time (RTT)

QUIC endpoints measure the delay incurred between when a packet is received and when the corresponding acknowledgment 
is sent, allowing a peer to maintain a more accurate RTT estimate than TCP.

At a high level, an endpoint measures the time from when a packet was sent to when it is acknowledged as an RTT sample. 
The endpoint uses RTT samples and peer-reported host delays to generate a statistical description of the network path's 
RTT. An endpoint computes the following three values for each path: the minimum value over a period of time (min_rtt), 
an exponentially weighted moving average (smoothed_rtt), and the mean deviation (referred to as "variation") in the 
observed RTT samples (rttvar).

## Helpful Links

* The Illustrated QUIC Connection at https://quic.xargs.org/