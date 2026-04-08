# crypto-lab-aes-modes

> **`AES-128` · `AES-256` · `GCM` · `CBC` · `CTR` · `ECB` · `CCM`**

**[▶ Live Demo](https://systemslibrarian.github.io/crypto-lab-aes-modes/)**

An interactive, browser-based demonstration of AES block cipher modes of operation — ECB, CBC, CTR, GCM, and CCM — showing how mode choice dramatically affects security properties, with a live padding oracle attack demonstration.

---

## 1. What It Is

This project is an interactive demo of `AES-128` and `AES-256` used with `ECB`, `CBC`, `CTR`, `GCM`, and `CCM`, along with a live CBC padding oracle attack. AES is a **symmetric** block cipher, and the mode determines whether you get confidentiality only (`ECB`, `CBC`, `CTR`) or authenticated encryption (`GCM`, `CCM`). These modes solve the practical problem of encrypting messages longer than one block while handling IVs/nonces and, in the AEAD cases, integrity for ciphertext and `AAD`. The demo is educational: it shows real behavior and failure cases, but it is not a new cryptographic protocol.

## 2. When to Use It

- **Use `GCM` for general-purpose application and transport encryption.** It gives confidentiality and authenticity together, which is why the demo marks it as the recommended default.
- **Use `CCM` in constrained or embedded environments that already standardize on it.** The code and UI describe it as a two-pass AEAD mode suited to low-power protocols.
- **Use `CTR` only when you can guarantee a unique counter/nonce and add separate integrity protection.** It behaves like a stream cipher and fails badly if a nonce is ever reused.
- **Use `CBC` only for legacy interoperability, with an unpredictable `IV` and Encrypt-then-MAC.** The demo shows that confidentiality alone is not enough.
- **Do not use `ECB` for multi-block data.** Repeated plaintext blocks remain repeated in the ciphertext and leak structure.

## 3. Live Demo

**[▶ Live Demo](https://systemslibrarian.github.io/crypto-lab-aes-modes/)**

The demo lets you encrypt plaintext in `ECB`, `CBC`, `CTR`, `GCM`, and `CCM`, then inspect the resulting key, `IV`/nonce, ciphertext, and authentication data where applicable. It also includes an image upload for the ECB pattern-leakage demo, a manual `IV` input for CBC, a two-message nonce reuse setup for CTR, `AAD` and `Tag Length (bits)` controls for GCM, and step-by-step controls for the padding oracle attack. It demonstrates encryption, tamper detection, and attack behavior rather than a general-purpose decrypt workflow.

## 4. What Can Go Wrong

- **`ECB` pattern leakage:** identical plaintext blocks encrypt to identical ciphertext blocks, so message structure remains visible.
- **CBC padding oracle exposure:** if a system reveals whether `PKCS#7` padding is valid, an attacker can recover the plaintext byte by byte.
- **CBC bit-flipping:** without authentication, modifying one ciphertext block predictably changes bits in the next plaintext block.
- **`CTR` or `GCM` nonce reuse:** reusing the same `(key, nonce)` pair leaks relationships between messages, and in GCM can enable forgery attacks.
- **GCM tag truncation:** shorter authentication tags reduce forgery resistance, which is why the UI marks 128-bit tags as the recommended choice.

## 5. Real-World Usage

- **TLS 1.2 / TLS 1.3:** AES-GCM protects application records in mainstream HTTPS deployments.
- **QUIC / HTTP/3:** AES-GCM is one of the standard AEAD choices for packet protection.
- **WPA2/WPA3 (`CCMP`):** Wi-Fi uses AES-CCM to encrypt and authenticate data frames.
- **Bluetooth Low Energy:** BLE uses AES-CCM at the link layer for confidentiality and message authentication.
- **Zigbee / IEEE 802.15.4:** low-power mesh networking standards use the CCM family for authenticated encryption.

## Related Demos

- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — ChaCha20-Poly1305 AEAD
- [crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/) — AES encryption demo
- [crypto-lab-iron-serpent](https://systemslibrarian.github.io/crypto-lab-iron-serpent/) — Serpent cipher demo
- [crypto-compare](https://systemslibrarian.github.io/crypto-compare/) — Symmetric cipher comparison
- [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — Full demo collection

---

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."* — 1 Corinthians 10:31