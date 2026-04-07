# crypto-lab-aes-modes

> **`AES-128` · `AES-256` · `GCM` · `CBC` · `CTR` · `ECB` · `CCM`**

**[▶ Live Demo](https://systemslibrarian.github.io/crypto-lab-aes-modes/)**

An interactive, browser-based demonstration of AES block cipher modes of operation — ECB, CBC, CTR, GCM, and CCM — showing how mode choice dramatically affects security properties, with a live padding oracle attack demonstration.

---

## Overview

This demo lets you encrypt data with five different AES modes side-by-side and see exactly how each mode behaves — including their vulnerabilities. All cryptographic operations use the **WebCrypto API** for real AES encryption (no simulated math, no pure-JS reimplementations). CCM mode uses [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) since WebCrypto does not support CCM natively.

## Modes Covered

| Mode | Status | Description |
|------|--------|-------------|
| **ECB** | 🔴 AVOID | Electronic Codebook — identical blocks produce identical ciphertext (NIST SP 800-38A) |
| **CBC** | 🟡 LEGACY | Cipher Block Chaining — classic mode, vulnerable to padding oracle and bit-flip attacks (NIST SP 800-38A) |
| **CTR** | 🟢 ACCEPTABLE | Counter mode — stream cipher construction, catastrophic on nonce reuse (NIST SP 800-38A) |
| **GCM** | 🟢 RECOMMENDED | Galois/Counter Mode — authenticated encryption with AAD (NIST SP 800-38D) |
| **CCM** | 🟢 ACCEPTABLE | Counter with CBC-MAC — two-pass AEAD for constrained environments (RFC 3610, NIST SP 800-38C) |
| **Padding Oracle** | ⚔️ ATTACK | Live CBC padding oracle attack — recovers plaintext using only padding validity responses |

## Primitives Used

- **AES-128** — ECB panel (via AES-CBC with zero IV for single-block ECB equivalence)
- **AES-256** — CBC, CTR, GCM panels (WebCrypto)
- **AES-128-CCM** — CCM panel (@noble/ciphers)
- **PKCS#7 padding** — CBC and padding oracle panels
- **GHASH** — GCM authentication tag computation
- **CBC-MAC** — CCM authentication

## Running Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-aes-modes.git
cd crypto-lab-aes-modes
npm install
npm run dev
```

Open [http://localhost:5173/crypto-lab-aes-modes/](http://localhost:5173/crypto-lab-aes-modes/) in your browser.

## Security Notes

- **ECB is never safe for multi-block data.** Identical plaintext blocks always produce identical ciphertext blocks, leaking message structure.
- **CBC requires Encrypt-then-MAC.** Without integrity protection, CBC is vulnerable to padding oracle attacks that recover the entire plaintext.
- **GCM nonce must never repeat.** Nonce reuse with GCM allows forgery attacks and key recovery via the GHASH polynomial.
- **GCM tag truncation** reduces forgery resistance — per NIST SP 800-38D §5.2.1.2, tags shorter than 96 bits are not recommended.
- **CTR nonce reuse** is catastrophic — XORing two ciphertexts encrypted with the same nonce yields the XOR of the plaintexts.

> **ECB implementation note:** WebCrypto does not support ECB natively. This demo implements ECB by encrypting each 16-byte block individually using AES-CBC with a zero IV, which for a single block is mathematically equivalent to ECB encryption.

## Accessibility

This demo targets **WCAG 2.1 AA** compliance:

- All interactive elements have descriptive ARIA labels
- Full keyboard navigation — logical tab order, no keyboard traps
- Arrow key navigation within tab bar (Home/End supported)
- Visible focus indicators in both dark and light modes (minimum 3:1 contrast ratio)
- Status chips have text equivalents — color is never the sole indicator
- Animations respect `prefers-reduced-motion`
- Error states announced via `aria-live` regions
- Minimum 4.5:1 contrast ratio for normal text, 3:1 for large text
- Screen reader navigable throughout

## Why This Matters

Mode choice is the most commonly misunderstood AES decision. ECB mode is *still* found in production systems in 2026. Choosing the wrong mode can render AES encryption completely ineffective — leaking plaintext structure, enabling bit-flip attacks, or allowing full plaintext recovery through padding oracles.

## Related Demos

- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — ChaCha20-Poly1305 AEAD
- [crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/) — AES encryption demo
- [crypto-lab-iron-serpent](https://systemslibrarian.github.io/crypto-lab-iron-serpent/) — Serpent cipher demo
- [crypto-compare](https://systemslibrarian.github.io/crypto-compare/) — Symmetric cipher comparison
- [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — Full demo collection

---

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."* — 1 Corinthians 10:31