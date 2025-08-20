# trio-quicly
Reference implementation of QUIC-LY transport protocol (which is QUIC without encryption) using the [Python Trio][_Trio] framework.

## QUIC-LY

**QUIC-LY** stands for **QUIC Lean Yet-reliable** — a minimalist, unencrypted variant of the QUIC transport protocol. Built for Python, QUIC-LY emphasizes simplicity, ordered delivery, and congestion control with as little overhead as possible.

---

## 🚀 Overview

QUIC-LY is designed for use cases where encryption is not required, but reliability and efficiency still matter — such as controlled environments, internal RPC systems, or research/prototyping.

It trims down the original QUIC protocol by removing TLS, reducing metadata, and focusing on just what you need:  
**Reliable delivery, congestion control, and stream multiplexing — without the crypto baggage.**

QUIC-LY is a simplified version of QUIC for educational and experimental purposes.  
It omits encryption, focusing on core transport functionality.

QUIC v1 was standardized in May 2021 in [RFC 9000][_RFC 9000] and accompanied by [RFC 9002][_RFC 9002] ("QUIC Loss Detection and Congestion Control").  

---

## ✨ Features

- 🚫 **No encryption** — Designed for trusted networks
- ✅ **Reliable, ordered delivery**
- 📦 **Stream multiplexing** (QUIC-style)
- 📉 **Built-in congestion control**
- 🧠 **Simple, readable Python 3 codebase**
- 🛠️ **Extensible for experimentation and research**

---

## Design Goals

- Easy to understand and modify
- Based on Python and the Trio async framework
- Close adherence to the IETF QUIC transport specification (minus TLS) including Loss Detection and Congestion Control.

## Project Layout

- `quicly/` — Core protocol logic
- `examples/` — Sample client/server apps
- `tests/` — Unit tests

## Requirements

- Python 3.11+
- [Python Poetry](https://python-poetry.org/)

## Getting Started

Install Poetry if you don't have it
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Install project dependencies
```bash
poetry install
```

Activate the virtual environment and run examples
```bash
poetry run python examples/server.py
poetry run python examples/client.py
```

[_Trio]: https://trio.readthedocs.io/en/stable/
[_RFC 9000]: https://datatracker.ietf.org/doc/html/rfc9000
[_RFC 9002]: https://datatracker.ietf.org/doc/html/rfc9002
