# Project Oubliette

![Status](https://img.shields.io/badge/Status-Research_Prototype-red)
![License](https://img.shields.io/badge/License-GPLv3-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-yellow)

**A Zero-Trust Endpoint Data Protection & Remote Key Management System.**

# 🚨 Pre-Alpha
# Early development phase. Core concepts are being explored; a working prototype is not yet available.



---

## 📖 Project Overview

**Project Oubliette** is an experimental security architecture designed to research advanced **Data Leak Prevention (DLP)** strategies for high-value endpoints.

The core objective is to mitigate the risk of data breaches resulting from physical device theft or unauthorized access. Unlike traditional Full Disk Encryption (FDE) where keys are stored locally (TPM/Disk), Oubliette implements a **decoupled key architecture**.

The system mounts encrypted containers as virtual local drives, but decryption keys are fetched from a secure remote server only after successful multi-factor authentication. Keys are injected directly into volatile memory (RAM) and **never touch the persistent storage**, effectively neutralizing "Data-at-Rest" attacks on compromised devices.

## 🚀 Key Features

* **Zero-Knowledge Architecture:** The server acts as a Key Management System (KMS) that stores wrapped keys but cannot decrypt them without the client's master secret.
* **Volatile Key Handling:** Decryption keys exist only in RAM. If the device is powered off or the connection is severed, the keys vanish, rendering the data cryptographically inaccessible.
* **AES-256 XTS Encryption:** Utilizes industry-standard, high-performance encryption modes for robust data confidentiality.
* **Emergency Cryptographic Sanitization:** Includes a specialized protocol for compromised scenarios. If a specific "Emergency Token" is triggered during authentication, the server performs an immediate destruction of the key material, rendering the local data permanently unrecoverable (Remote Wipe).
* **FUSE/WinFsp Integration:** Seamless integration with the OS file system, appearing as a standard drive to the user.

## 🛠️ Technical Architecture

This project demonstrates skills in **System Programming**, **Applied Cryptography**, and **Secure Network Design**.

* **Client Side:** Python 3.10+, PyCryptodome (Crypto primitives), FUSE (Linux) / WinFsp (Windows).
* **Server Side:** Python FastAPI (High-performance Async I/O), SQLite/PostgreSQL.
* **Security Stack:**
    * Encryption: AES-256 in XTS mode.
    * Key Derivation: Argon2 (Memory-hard password hashing).
    * Transport Security: TLS 1.3 enforcement.

## ⚠️ Disclaimer & Research Notice

**FOR EDUCATIONAL AND DEFENSIVE SECURITY RESEARCH PURPOSES.**

This project is a **Proof-of-Concept (PoC)** intended to explore secure storage architectures and cryptographic key handling. It is **NOT** a commercial product and has not undergone a third-party security audit.

* **Data Safety:** The "Emergency Sanitization" feature is **destructive by design**. Use with extreme caution in testing environments.
* **Use Case:** This tool is designed to demonstrate methods for protecting Intellectual Property (IP) and sensitive PII (Personally Identifiable Information) in high-risk environments (e.g., corporate laptops in field operations).

The author assumes no liability for data loss or misuse of this software. Users are responsible for ensuring compliance with applicable local laws and data protection regulations.

## 📦 Roadmap

*(Documentation is currently being updated for the Pre-Alpha release)*

- [ ] Core Encryption Engine Implementation
- [ ] Client-Server Secure Handshake (TLS)
- [ ] FUSE/WinFsp Mount Logic
- [ ] Emergency Wipe Protocol Implementation
