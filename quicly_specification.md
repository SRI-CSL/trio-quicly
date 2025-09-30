---
title: "QUIC-LY: A Minimal QUIC Transport without TLS"
abbrev: QUIC-LY
docname: draft-sri-quicly-00
category: exp
ipr: trust200902
area: Transport
workgroup: (none)
keyword: Internet-Draft
author:
  - ins: L. Briesemeister
    name: Linda Briesemeister
    org: SRI International
    street: 333 Ravenswood Ave
    city: Menlo Park
    region: CA
    code: 94025
    country: USA
    email: linda.briesemeister@sri.com
normative:
  RFC8999: RFC8999
  RFC9000: RFC9000
  RFC9002: RFC9002
informative:
  RFC9001: RFC9001
  RFC9221: RFC9221
  RFC9368: RFC9368

--- abstract

QUIC-LY is an experimental variant of QUIC intended for controlled environments where both endpoints are managed by a single operator and no confidentiality is required. QUIC-LY removes TLS-based packet protection and replaces the QUIC/TLS handshake with a concise, 1-RTT transport setup using a small CONFIG/CONFIG-ACK exchange. QUIC-LY preserves QUIC’s transport benefits (multiplexed streams, flow control, loss recovery, connection migration) while operating entirely in cleartext. QUIC-LY is not intended for the public Internet.

--- middle

# Introduction

QUIC {{RFC9000}} couples a transport protocol with TLS 1.3 {{RFC9001}} for key establishment and packet protection. QUIC-LY is a deliberately simplified variant intended for closed, trusted deployments where encryption is unnecessary and endpoints are under common control. QUIC-LY removes TLS, disables packet and header protection, and introduces a compact transport parameter exchange (CONFIG/CONFIG-ACK) to reach steady state in one round trip.

QUIC-LY retains QUIC’s invariants {{RFC8999}}, stream and flow control mechanisms, loss recovery {{RFC9002}}, and connection migration capability, unless otherwise stated. QUIC-LY is not suitable for deployment on the open Internet.

# Conventions and Terminology

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”, “SHOULD NOT”, “RECOMMENDED”, “NOT RECOMMENDED”, “MAY”, and “OPTIONAL” in this document are to be interpreted as described in BCP 14 when, and only when, they appear in all capitals, as shown here.

Terminology otherwise follows QUIC Transport {{RFC9000}}.

# Overview

QUIC-LY establishes a connection in one round trip, without TLS:

* Client sends an Initial packet using QUIC-LY’s version with a CONFIG frame (optionally empty if defaults are used), any Stream data desired, and padding to reach a configured size (Section {{packet-types-and-headers}}).
* Server responds with ACK (for the Initial) and CONFIG-ACK (if needed to override defaults or client values). Both endpoints then consider the connection established and proceed with Short Header packets.

The CONFIG/CONFIG-ACK exchange carries a compact set of transport parameters using TLVs. Operators MAY omit CONFIG entries entirely and rely on prearranged defaults.

Note that the Initial packet from client to server must carry a payload of at least 1 Byte to conform with QUIC. Therefore, an empty CONFIG frame is minimally required.

# Version and Scope

QUIC-LY uses QUIC version `0x51554c59` (ASCII “QULY”). Endpoints that do not support this version MUST silently discard such packets. Version negotiation is not defined. QUIC-LY is intended only for environments where both endpoints are controlled and configured to support this version.

# Packet Protection and Wire Image

QUIC-LY does not use TLS and does not provide header protection or payload encryption. Packets are sent in cleartext. The QUIC-LY wire image adheres to QUIC invariants {{RFC8999}}. Implementations SHOULD use the same encoding rules as {{RFC9000}}, but packet contents are not cryptographically protected.

Operators MUST assume that on-path observers can read, modify, and inject QUIC-LY packets. QUIC-LY is therefore RECOMMENDED only in closed, trusted networks.

# Packet Types and Headers {#packet-types-and-headers}

QUIC-LY uses the QUIC Long and Short Header formats from {{RFC9000}}. Fields are interpreted as in QUIC, with the following differences:

* No Initial/Handshake/1-RTT keys are derived or used.
* CRYPTO and HANDSHAKE_DONE frames are not used.
* Endpoints MAY send Short Header packets immediately after the server’s first flight.

By default, a client Initial pads the UDP payload to at least 1200 bytes. QUIC-LY makes this configurable via the `initial_padding_target` transport parameter (Section {{transport-parameters-tlvs}}). Endpoints SHOULD pad the Initial to the agreed target. Any non-negative value is valid; **0 means no padding**. Operators are advised to review amplification guidance in Section {{address-validation-and-amplification}} before reducing the padding target.

# Frames

## Allowed/Disallowed Frames

Allowed: STREAM, RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAMS, MAX_STREAM_DATA, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, PADDING, ACK/ACK_ECN, CONNECTION_CLOSE, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, DATAGRAM (if supported) {{RFC9221}}.

Disallowed: CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, early-data related frames.

## CONFIG and CONFIG_ACK Frames

*Frame Type:* `0x3a` and `0x3b` (suggested; see IANA Considerations).

The Config frame conveys proposed transport parameters from client to server and confirmation or overriding settings in return. 

Its format is shown in Figure XX.

~~~
CONFIG Frame {
  Type (i) = 0x3a..0x3b,
  [Length (i)],
  TLV-List (..),  # Length bytes
}
~~~

If Length is omitted or 0 then the TLV-List has no entries.  Otherwise, the TLV-List is exactly Length bytes long.

Each Transport Paremeter as TLV is encoded as:

~~~
TLV {
  Param ID (i), 
  [Value Length (i)],
  Value (..)
}
~~~

Integers inside VALUE are QUIC varints unless otherwise stated. A parameter that is a boolean flag is encoded with `VALUE_LEN = 0` to mean true; absence means false.

The server replies with CONFIG-ACK to indicate the effective values that apply to the connection (accepted or clamped). Format is identical to CONFIG. Again, if the Length field is missing or 0, then all client suggested values are accepted. 

After receiving this response, the connection is established and the values in the server's CONFIG-ACK response take presedence.

## Transport Parameters (TLVs) {#transport-parameters-tlvs}

QUIC-LY defines the following minimal set. Unknown `PARAM_ID`s MUST be ignored (skipped) by the receiver. 
QUIC-LY uses the following subset of QUIC transport parameters and adds optional datagram support and padding targets.

| ID    | Name                                   | Type   | Units | Default (QUIC)            | QUIC |
|:------|:---------------------------------------|:-------|:------|:--------------------------|:-----|
| 0x01  | max_idle_timeout                       | varint | ms    | 0 (disabled if 0/absent)  | yes  |
| 0x03  | max_udp_payload_size                   | varint | bytes | 65527 (MUST be ≥ 1200)    | yes  |
| 0x04  | initial_max_data                       | varint | bytes | 0                         | yes  |
| 0x05  | initial_max_stream_data_bidi_local     | varint | bytes | 0                         | yes  |
| 0x06  | initial_max_stream_data_bidi_remote    | varint | bytes | 0                         | yes  |
| 0x07  | initial_max_stream_data_uni            | varint | bytes | 0                         | yes  |
| 0x08  | initial_max_streams_bidi               | varint | count | 0                         | yes  |
| 0x09  | initial_max_streams_uni                | varint | count | 0                         | yes  |
| 0x0a  | ack_delay_exponent                     | varint | —     | 3                         | yes  |
| 0x0b  | max_ack_delay                          | varint | ms    | 25                        | yes  |
| 0x0c  | disable_active_migration               | flag   | —     | absent ⇒ false            | yes  |
| 0x0e  | active_connection_id_limit             | varint | count | 2 (MUST be ≥ 2)           | yes  |
| 0x20  | max_datagram_frame_size                | varint | bytes | 0 (absent ⇒ no support)   | RFC9221 |
| 0x173 | initial_padding_target (QUIC-LY only)  | varint | bytes | 1200                      | no   |

If present, transport parameters that set initial per-stream flow control limits (initial_max_stream_data_bidi_local, 
initial_max_stream_data_bidi_remote, and initial_max_stream_data_uni) are equivalent to sending a MAX_STREAM_DATA 
frame on every stream of the corresponding type immediately after opening. If the transport parameter is absent, 
streams of that type start with a flow control limit of 0.

In QUIC-LY, if CONFIG and CONFIG_ACK frames are empty, apply the defaults from the table above.

### TLV Encoding Details and Example

A TLV is a compact **Type–Length–Value** item carried inside CONFIG / CONFIG-ACK frames. It is encoded as:

~~~
TLV {
  Param ID (i), 
  [Value Length (i)],
  Value (..)
}
~~~

Encoding rules:

- `PARAM_ID` and integer `VALUE`s use **QUIC varints** (RFC 9000):
  - `00` = 1‑byte varint (6‑bit value)
  - `01` = 2‑byte varint (14‑bit value)
  - `10` = 4‑byte varint (30‑bit value)
  - `11` = 8‑byte varint (62‑bit value)
- Boolean/flag parameters set **`VALUE_LEN = 0`** to mean **true**; absence means false.
- Unknown `PARAM_ID`s **MUST** be ignored (skipped using `VALUE_LEN`).
- If a parameter appears multiple times, the **last occurrence wins**.

**Example: `initial_padding_target = 1200`**

Here, `PARAM_ID = 0x09` (`initial_padding_target`), and the integer `1200` is encoded as a QUIC varint.

1) Encode `PARAM_ID`:

~~~
PARAM_ID = 0x09 → 1‑byte varint → 0x09
(bits: 00|001001)
~~~

2) Encode `VALUE_LEN` (length of the VALUE field in bytes):

~~~
varint(1200) uses 2 bytes → VALUE_LEN = 0x02
(bits: 00|000010)
~~~

3) Encode `VALUE = varint(1200)`:
- 1200 (0x04B0) fits in 14 bits ⇒ **2‑byte varint**
- For a 2‑byte varint, the first byte is `01` followed by the high 6 bits; the second byte is the low 8 bits.

~~~
high 6 bits = (1200 >> 8) & 0x3F = 0x04  → bits 000100
low 8  bits = 1200 & 0xFF        = 0xB0  → bits 10110000

first byte: 01|000100 = 0x44
second byte:           0xB0

VALUE bytes: 0x44 0xB0
~~~

4) **Resulting TLV bytes** (`PARAM_ID`, `VALUE_LEN`, `VALUE`):

~~~
09 02 44 B0
~~~

**CONFIG frame carrying just this single TLV**

A CONFIG frame is:

~~~
FRAME_TYPE (varint=0x3a) , LENGTH (varint) , TLV‑List
~~~

With a single TLV of 4 bytes, `LENGTH = 0x04`.

~~~
FRAME_TYPE = 0x3A
LENGTH     = 0x04
TLV‑List   = 09 02 44 B0

CONFIG bytes: 3A 04 09 02 44 B0
~~~

Flag example (`disable_active_migration = true`):

~~~
PARAM_ID = 0x08 , VALUE_LEN = 0 → bytes: 08 00
~~~


# Connection Establishment (1-RTT Setup)

**Client → Server (Initial):**

* Long Header, Version = `0x51554c59`.
* Frames: 
    * CONFIG (possibly empty TLV list if defaults are used).
    * Application STREAM data (optional).
    * PADDING to reach the configured target.

The INITIAL packet from the client to the server contains at a minimum a CONFIG frame, which could be empty (Length = 0 or omitted). This is because the original QUIC specification requires a payload of at least 1 byte.

**Server → Client (First Response):**

* Long Header, Version = `0x51554c59`.
* Frames:
    * ACK for the client Initial.
    * CONFIG-ACK with effective parameters (empty list if defaults used).
    * NEW_CONNECTION_ID (optional).
    * Application STREAM data (optional).

After the server’s first response, the client responds with an ACK frame for the server's INITIAL.
When both endpoints have received an ACK of their INITIAL packet, they consider the connection established and SHOULD 
use Short Header packets.

# Address Validation and Amplification {#address-validation-and-amplification}

QUIC-LY deployments in controlled environments MAY disable Retry and tokens. Servers SHOULD apply an anti-amplification limit of at most three times (3x) the number of bytes received from the client address until that address is considered validated. When the negotiated or default `initial_padding_target` is less than 1200 bytes (including 0, meaning no padding), this limit can substantially reduce the size of the server's first flight. Operators MAY configure policy to permit a small first response even with small client initials; a simple rule is to cap the first flight to `max(3× bytes received, initial_padding_target)`. In tightly controlled labs, operators MAY disable amplification limits entirely.

# Connection IDs and Migration

QUIC-LY uses NEW_CONNECTION_ID and RETIRE_CONNECTION_ID as in {{RFC9000}}. PATH_CHALLENGE/PATH_RESPONSE MAY be used to validate a new path before migrating.

# Flow Control

QUIC-LY uses connection- and stream-level flow control as in {{RFC9000}} with limits established by CONFIG/CONFIG-ACK or defaults. Limits MAY be raised during the connection using MAX_DATA and MAX_STREAM_DATA.

# DATAGRAM Support

QUIC-LY supports sending data in DATAGRAM frames according to {{RFC9221}} if the respective transport parameter is set 
to something larger than zero.  Endpoints that support unreliable messages advertise `max_datagram_frame_size > 0`. 
Endpoints MUST NOT send DATAGRAM frames to a peer that did not advertise support.

DATAGRAM frames are ack-eliciting and congestion-controlled. They are not retransmitted by the transport and are not 
subject to stream flow control.

Endpoints MUST discard DATAGRAM frames that exceed their configured maximum size; this is not a connection error.

# Loss Detection and Recovery {#recovery}

QUIC-LY adopts the algorithms and timers of {{RFC9002}}. ACK generation, ACK delay, and probe timeouts follow QUIC norms, minus cryptographic key phases. 

One notable difference to QUIC is the absence of packet number spaces. As no packet protection exists in QUIC-LY and all packets and frames are transmitted in cleartext, we allow the ACK Frame to acknowledge receiving the server's Initial packet to be carried in a 1-RTT packet from the client to the server. This is different from {{RFC9000}}, which states that "ACK frames MUST only be carried in a packet that has the same packet number space as the packet being acknowledged."

# Timers and Timeouts {#timers}

This section defines QUIC-LY’s reliability and timeout behavior. It is aligned with QUIC’s
loss-detection timers {{RFC9002}} and the idle timeout and closing/draining semantics in {{RFC9000}},
adapted to QUIC-LY’s TLS-free setup.

## Probe Timeout (PTO) 

PTO is computed as in {{RFC9002}}:

~~~
PTO_base = SRTT + max(4 * RTTVAR, kGranularity) + max_ack_delay
~~~

with a small `kGranularity` (e.g., 1–10 ms) and `max_ack_delay` taken from the peer’s transport parameters (or 0 ms 
during handshake when exchanging INITIAL packets).

### PTO for Initial Packets

Endpoints maintain a Probe Timeout (PTO) for the Initial packets. Before any RTT sample is available, 
endpoints MUST use:

* `initial_rtt = 333 ms` (as in QUIC),
* `max_ack_delay = 0 ms` for the Initial packets (to avoid handshake deadlock).

A PTO MUST be armed whenever there are ack-eliciting Initial packets in flight and no ACK has
yet been received that newly acknowledges at least one of them.

### PTO in ESTABLISHED (for 1-RTT Packets)

QUIC-LY uses a single packet number space (see {{recovery}}) across the handshake and established phases. 
After ESTABLISHED, endpoints maintain one PTO for Short Header operation.

Arm or keep armed whenever at least one ack-eliciting packet is in flight. If the in-flight ack-eliciting packet/bytes 
number transitions from empty to non-empty, arm to `now + PTO_base * 2^pto_count` with `pto_count = 0`.

Cancel when no ack-eliciting packets remain in flight, i.e., when transitioning from non-empty to empty, or when 
entering CLOSING or DRAINING.

If an ACK newly acknowledges any ack-eliciting packet, update RTT using the ACK’s delay 
(scaled by ack_delay_exponent) and set `pto_count = 0`. Then, if ack-eliciting packets remain in flight, re-arm to 
`now + PTO_base`, or cancel the PTO otherwise.
If the ACK is a duplicate (no newly acknowledged packets), leave the PTO unchanged.

When the PTO Timer expires, send an ack-eliciting probe immediately with an ack-eliciting packet. 
Count probes as ack-eliciting in-flight data. 
Do not declare loss solely due to PTO firing. 
Increase backoff (`pto_count += 1`) and re-arm to `now + PTO_base * 2^pto_count`. 
Endpoints MAY send two ack-eliciting packets on PTO expiration if congestion control permits.

### What to Send When PTO Fires

When the Initial packet PTO expires, the endpoint MUST send an ack-eliciting Initial packet
as a "probe" packet. In QUIC-LY, the probe from the client SHOULD be a retransmission of the most
recent CONFIG frame (idempotent), optionally with PADDING up to the current
`initial_padding_target` (Section {{transport-parameters-tlvs}}). If the server's PTO for an Initial 
packet fires, it will create an updated ACK Frame (with any additional packet numbers seen since, if any) 
and the CONFIG_ACK frame if it was included in the first Initial packet.

On consecutive PTO expirations without receiving an ACK, the PTO MUST be exponentially backed
off (doubled) per {{RFC9002}}.

## Handshake Completion

An endpoint leaves the handshake phase and enters ESTABLISHED as follows:

* **Client**: when it has (1) received an ACK covering the client’s Initial and (2) processed the
  server’s CONFIG-ACK. If the server does not send CONFIG-ACK, the client MAY proceed using
  defaults after the first server response.
* **Server**: after receiving an ACK for one of its Initial packets.

Upon entering ESTABLISHED, endpoints SHOULD send Short Header packets.

## Handshake Timeout (Give-up Policy)

QUIC does not specify a fixed “handshake timeout” but uses a `max_idle_timeout` transport parameter.  Until we 
harmonize QUIC and QUIC-LY transport parameters; see [Issue 12](https://github.com/SRI-CSL/trio-quicly/issues/12), 
we use the QUIC-LY transport parameter `idle_timeout_ms` to be applied to both, established connections and 
handshaking. For QUIC-LY, an endpoint SHOULD abort the handshake if it has not reached ESTABLISHED after the elapsed 
time exceeds the endpoint’s configured `idle_timeout_ms` transport parameter.

To abort, the endpoint SHOULD send CONNECTION_CLOSE (with an appropriate error code) and
enter DRAINING.

## Interaction with Closing and Draining

If an endpoint initiates close at any time, it sends CONNECTION_CLOSE, enters CLOSING, and
sends no new application data. During CLOSING it MAY retransmit CONNECTION_CLOSE in response to
incoming ack-eliciting packets. After a short deadline (e.g., 3 × PTO), it MUST enter
DRAINING and send nothing further. If an endpoint receives a CONNECTION_CLOSE at any time,
it MUST immediately enter DRAINING and send nothing further until the drain period ends.

## Idle Timeout

Independently of the above, if no ack-eliciting packets are received for longer than
`idle_timeout_ms`, the endpoint MAY silently close the connection.

# Error Handling

QUIC-LY reuses QUIC Transport error codes where applicable. The following additional error codes are defined for CONNECTION_CLOSE (and potentially application close), encoded as QUIC varints:

* `QUICLY_MALFORMED_CONFIG (0xface01)`: The CONFIG or CONFIG-ACK frame is not well-formed or violates encoding rules.
* `QUICLY_UNSUPPORTED_PARAM (0xface02)`: A required parameter is unsupported by the peer.

Endpoints MUST ignore unknown CONFIG parameters and only fail the connection when a required parameter is missing or invalid by local policy.

# Security Considerations

QUIC-LY provides no confidentiality or integrity. On-path adversaries can read, modify, inject, or drop packets. Operators MUST deploy QUIC-LY only in closed, trusted networks or testbeds where these risks are acceptable.

Optional lightweight integrity: An operator MAY define an application-level integrity check (e.g., a per-connection MAC carried in the first application message and echoed) to reduce trivial teardown or frame-injection attacks. Such mechanisms are out of scope here.

# IANA Considerations

This document makes no requests of IANA. The frame type values `0x3a` and `0x3b` are suggested for private experiments and MUST NOT be used on the open Internet. The version number `0x51554c59` is for private use only.

# Manageability and Measurement

QUIC-LY packets are plaintext. Standard operational tools (e.g., flow logs, packet captures) can observe transport fields directly. The QUIC spin bit behavior, if implemented, follows {{RFC9000}}.

# References

## Normative References

* {{RFC8999}}
* {{RFC9000}}
* {{RFC9002}}

## Informative References

* {{RFC9001}}
* {{RFC9221}}
* {{RFC9368}}

# Appendix A. Pseudocode for CONFIG/CONFIG-ACK

The following illustrates TLV serialization. QUIC varint encoding is as defined in {{RFC9000}}. Examples are illustrative, not normative.

~~~
encode_config(map):
  body = []
  for (id, val) in map:
    emit varint(id)
    if val is flag_true:
      emit varint(0)
    elif val is flag_false:
      pass  # omit value length and value
    else:
      tmp = encode_as_varint_bytes(val)
      emit varint(len(tmp))
      emit tmp
  return varint(0x3a) || varint(len(body)) || body

parse_config(bytes):
  ftype = read_varint()
  assert ftype in {0x3a, 0x3b}
  L = read_varint()
  end = pos + L
  out = {}
  while pos < end:
    pid = read_varint()
    vlen = read_varint() if pos < end else vlen = -1
    if pid is flag:
      if vlen == 0:
        out[pid] = flag_true
     else:
        out[pid] = flag_false
    else:  # if pid known:
      val = read(vlen)
      out[pid] = val
  return out
~~~

# Appendix B. Minimal State Machines

**Client states:** `START → WAIT_FIRST → ESTABLISHED → CLOSING → DRAINING`

START: Send Initial (ver=`0x51554c59`) with CONFIG frame (potentially empty), optional application data (STREAM or DATAGRAM frames), and padding to the configured target; enter `WAIT_FIRST`.

WAIT_FIRST: On receiving server ACK of the Initial (CONFIG-ACK, possibly empty), apply parameters and enter `ESTABLISHED`. Ignore any Version Negotiation. On receiving CONNECTION_CLOSE, enter `DRAINING`.

ESTABLISHED: Use Short Header packets with STREAM/ACK/flow control. When application wants to close, send CONNECTION_CLOSE frame and enter `CLOSING`.

CLOSING: On receiving CONNECTIONC_CLOSE, enter `DRAINING`.

**Server states:** `LISTEN → ESTABLISHED → CLOSING → DRAINING`

LISTEN: On client Initial (ver=`0x51554c59`), parse CONFIG (if any), respond with ACK and CONFIG-ACK (possibly empty); enter `ESTABLISHED`.

ESTABLISHED: Normal operation until server initiates closing by sending CONNECTION_CLOSE, enter `CLOSING`, or until receiving CONNECTION_CLOSE, then enter `DRAINING`.

# Appendix C. Interoperability Notes

* If CONFIG/CONFIG-ACK are empty, endpoints use local defaults.
* When `initial_padding_target` < 1200, re-evaluate anti-amplification policy.
* Unknown CONFIG parameters MUST be ignored to allow evolution.