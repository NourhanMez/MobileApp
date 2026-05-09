# CipherChat — TP2 · Cryptography & Access Control
## Python (Flask) + HTML/CSS/JS Mobile Web App

---

## Features

### Required (TP2)
| # | Requirement | Implementation |
|---|-------------|---------------|
| 1 | **Message sent encrypted** | AES-256-CBC encrypts the message; RSA-2048-OAEP encrypts the AES key |
| 2 | **Read-only messages** | Flag blocks copy/context-menu on received side; badge shown |
| 3 | **PKI-based home-made system** | **Public key** (RSA) used for initial key exchange; **Symmetric** (AES-256) encrypts messages |
| 4 | **Extra features** | See table below |

### Extra Features
| Feature | Details |
|---------|---------|
| **Digital Signatures** | Every encrypted msg signed with RSA-PSS-SHA256; verified on receipt |
| **Tamper Detection** | Invalid signature = decryption error shown |
| **Self-destructing messages** | TTL options: 10s / 30s / 60s / 5min — server drops expired messages |
| **Key Fingerprint** | SHA-256 of public key shown per user for identity verification |
| **PKI Step Animator** | Live step-by-step animation when sending |
| **Message Detail Sheet** | Tap any bubble to see encryption metadata |
| **Key Info Screen** | Full RSA keypair viewer with algorithm details |
| **Multi-user** | Register multiple accounts; real encrypted threads between any two |

---

## Encryption Flow (PKI Hybrid)

```
── SEND ─────────────────────────────────────────────────────
① Generate random AES-256 session key  (symmetric speed)
② Encrypt plaintext   →  AES-256-CBC(sessionKey, IV)
③ Encrypt sessionKey  →  RSA-OAEP-SHA256(recipient.publicKey)
④ Sign ciphertext     →  RSA-PSS-SHA256(sender.privateKey)
⑤ Transmit { encryptedKey, iv, ciphertext, signature }

── RECEIVE ──────────────────────────────────────────────────
① Verify signature    →  RSA-PSS(sender.publicKey)
② Decrypt sessionKey  →  RSA-OAEP(recipient.privateKey)
③ Decrypt ciphertext  →  AES-256-CBC(sessionKey, IV)
```

---

## Setup & Run

### 1. Install dependencies
```bash
pip install flask cryptography
```

### 2. Run the server
```bash
python app.py
```

### 3. Open in browser
```
http://localhost:5000
```

> **For mobile:** find your computer's local IP (e.g. `192.168.1.x`) and open `http://192.168.1.x:5000` on your phone — same Wi-Fi required.

### 4. Demo accounts (pre-seeded)
| Username | Password  |
|----------|-----------|
| Alice    | alice123  |
| Bob      | bob123    |

> Open two browser tabs — log in as Alice in one, Bob in the other.  
> Send an encrypted message from Alice → Bob, then switch to Bob's tab to see it decrypted.

---

## File Structure

```
cipherchat_web/
  app.py              ← Flask backend: PKI engine + REST API
  static/
    index.html        ← Full mobile UI (HTML + CSS + JS, single file)
  README.md
```
