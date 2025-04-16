# Some Notes on QUIC Definitions and Nomenclature

Ack-eliciting Packet
: A QUIC Packet that contains frames other than ACK, PADDING, and CONNECTION_CLOSE. These cause a recipient to send an 
acknowledgment.

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


## Helpful Links

* The Illustrated QUIC Connection at https://quic.xargs.org/