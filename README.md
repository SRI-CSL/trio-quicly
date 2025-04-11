# trio-quicly
Reference implementation of QUIC-LY transport protocal using the Python Trio framework.

## QUIC-LY

**QUIC-LY** stands for **QUIC Lean Yet-reliable** — a minimalist, unencrypted variant of the QUIC transport protocol. Built for Python, QUIC-LY emphasizes simplicity, ordered delivery, and congestion control with as little overhead as possible.

---

## 🚀 Overview

QUIC-LY is designed for use cases where encryption is not required, but reliability and efficiency still matter — such as controlled environments, internal RPC systems, or research/prototyping.

It trims down the original QUIC protocol by removing TLS, reducing metadata, and focusing on just what you need:  
**Reliable delivery, congestion control, and stream multiplexing — without the crypto baggage.**

---

## ✨ Features

- 🚫 **No encryption** — Designed for trusted networks
- ✅ **Reliable, ordered delivery**
- 📦 **Stream multiplexing** (QUIC-style)
- 📉 **Built-in congestion control**
- 🧠 **Simple, readable Python 3 codebase**
- 🛠️ **Extensible for experimentation and research**

---

## 📦 Installation
