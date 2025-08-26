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

* Client sends an Initial packet using QUIC-LY’s version with a CONFIG frame (optional) and padding to reach a configured size (Section {{packet-types-and-headers}}).
* Server responds with ACK (for the Initial) and CONFIG-ACK (if needed). Both endpoints then consider the connection established and proceed with Short Header packets.

The CONFIG/CONFIG-ACK exchange carries a compact set of transport parameters using TLVs. Operators MAY omit CONFIG entirely and rely on prearranged defaults.

# Version and Scope

QUIC-LY uses QUIC version `0x51554c59` (ASCII “QULY”). Endpoints that do not support this version MUST silently discard such packets. Version negotiation is not defined. QUIC-LY is intended only for environments where both endpoints are controlled and configured to support this version.

# Packet Protection and Wire Image

QUIC-LY does not use TLS and does not provide header protection or payload encryption. Packets are sent in cleartext. The QUIC-LY wire image adheres to QUIC invariants {{RFC8999}}. Implementations SHOULD use the same packet number spaces and encoding rules as {{RFC9000}}, but packet contents are not cryptographically protected.

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

## CONFIG Frame

*Frame Type:* `0x3a` (suggested; see IANA Considerations).

The CONFIG frame conveys proposed transport parameters from client to server. Its format is:

~~~
CONFIG = FRAME_TYPE (varint = 0x3a),
         LENGTH (varint),
         TLV-List (LENGTH bytes)
~~~

Each TLV is encoded as:

~~~
TLV = PARAM_ID (varint), VALUE_LEN (varint), VALUE (VALUE_LEN bytes)
~~~

Integers inside VALUE are QUIC varints unless otherwise stated. A parameter that is a boolean flag is encoded with `VALUE_LEN = 0` to mean true; absence means false.

## CONFIG-ACK Frame

*Frame Type:* `0x3b` (suggested; see IANA Considerations).

The server replies with CONFIG-ACK to indicate the effective values that apply to the connection (accepted or clamped). Format is identical to CONFIG.

## Transport Parameters (TLVs) {#transport-parameters-tlvs}

QUIC-LY defines the following minimal set. Unknown `PARAM_ID`s MUST be ignored (skipped) by the receiver.

| ID   | Name                         | Type   | Units |
|:-----|:-----------------------------|:-------|:------|
| 0x01 | initial_max_data             | varint | bytes |
| 0x02 | initial_max_stream_data_bidi | varint | bytes |
| 0x03 | initial_max_streams_bidi     | varint | count |
| 0x04 | max_udp_payload_size         | varint | bytes |
| 0x05 | idle_timeout_ms              | varint | ms    |
| 0x06 | ack_delay_exponent           | varint | —     |
| 0x07 | max_ack_delay_ms             | varint | ms    |
| 0x08 | disable_active_migration     | flag   | —     |
| 0x09 | initial_padding_target       | varint | bytes |

**RECOMMENDED defaults** (if CONFIG/CONFIG-ACK are omitted):

~~~
initial_max_data = 1,048,576; initial_max_stream_data_bidi = 262,144;
initial_max_streams_bidi = 8; max_udp_payload_size = 1350;
idle_timeout_ms = 30000; ack_delay_exponent = 3; max_ack_delay_ms = 25;
initial_padding_target = 1200; disable_active_migration = absent (false).
~~~

### TLV Encoding Details and Example

A TLV is a compact **Type–Length–Value** item carried inside CONFIG / CONFIG-ACK. It is encoded as:

~~~
TLV = PARAM_ID (varint) , VALUE_LEN (varint) , VALUE (VALUE_LEN bytes)
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
* Frames: CONFIG (optional), application STREAM data (optional), padding to reach the configured target.

**Server → Client (First Response):**

* ACK for the client Initial.
* CONFIG-ACK with effective parameters (optional if defaults used).
* NEW_CONNECTION_ID (optional), application STREAM data (optional).

After the server’s first response, both endpoints consider the connection established and SHOULD use Short Header packets.

# Address Validation and Amplification {#address-validation-and-amplification}

QUIC-LY deployments in controlled environments MAY disable Retry and tokens. Servers SHOULD apply an anti-amplification limit of at most three times (3x) the number of bytes received from the client address until that address is considered validated. When the negotiated or default `initial_padding_target` is less than 1200 bytes (including 0, meaning no padding), this limit can substantially reduce the size of the server's first flight. Operators MAY configure policy to permit a small first response even with small client initials; a simple rule is to cap the first flight to `max(3× bytes received, initial_padding_target)`. In tightly controlled labs, operators MAY disable amplification limits entirely.

# Connection IDs and Migration

QUIC-LY uses NEW_CONNECTION_ID and RETIRE_CONNECTION_ID as in {{RFC9000}}. PATH_CHALLENGE/PATH_RESPONSE MAY be used to validate a new path before migrating.

# Flow Control

QUIC-LY uses connection- and stream-level flow control as in {{RFC9000}} with limits established by CONFIG/CONFIG-ACK or defaults. Limits MAY be raised during the connection using MAX_DATA and MAX_STREAM_DATA.

# Loss Detection and Recovery

QUIC-LY adopts the algorithms and timers of {{RFC9002}}. ACK generation, ACK delay, probe timeouts, and packet number spaces follow QUIC norms, minus cryptographic key phases.

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
    vlen = read_varint()
    val = read(vlen)
    out[pid] = (flag_true if vlen == 0 else val)
  return out
~~~

# Appendix B. Minimal State Machines

**Client states:** `START → WAIT_FIRST → ESTABLISHED → CLOSING → DRAINING`

START: Send Initial (ver=`0x51554c59`) with optional CONFIG and padding to the configured target; enter `WAIT_FIRST`.

WAIT_FIRST: On receiving server ACK of the Initial (and optional CONFIG-ACK), apply parameters and enter `ESTABLISHED`. Ignore any Version Negotiation. On CONNECTION_CLOSE, enter `DRAINING`.

ESTABLISHED: Use Short Header packets with STREAM/ACK/flow control.

**Server states:** `LISTEN → ESTABLISHED → CLOSING → DRAINING`

LISTEN: On client Initial (ver=`0x51554c59`), parse CONFIG (if any), respond with ACK and CONFIG-ACK (if needed); enter `ESTABLISHED`.

ESTABLISHED: Normal operation.

# Appendix C. Interoperability Notes

* If CONFIG/CONFIG-ACK are omitted, endpoints use local defaults.
* When `initial_padding_target` < 1200, re-evaluate anti-amplification policy.
* Unknown CONFIG parameters MUST be ignored to allow evolution.