# Secure Diffie-Hellman and PAKE Protocol Implementation

This project demonstrates a step-by-step implementation of:

- ✅ Basic Diffie-Hellman key exchange  
- ✅ Secure Diffie-Hellman with **identity verification using ECC (ECDSA)**  
- ✅ Simplified OPAQUE protocol (a modern PAKE: Password-Authenticated Key Exchange)

---

## 📁 Project Structure

DF_exchange/

├── crypto_utils.py # Modular exponentiation, prime generation, ECC signing, HMAC, PBKDF2, etc.

├── dh_basic.py # Basic (insecure) Diffie-Hellman

├── dh_signed.py # Secure DH with ECC-based identity verification (ECDSA)

├── pake_opaque_demo.py # Simplified OPAQUE protocol (PAKE)

├── dh_mitm_demo.py # Demonstrates MITM attack success vs failure

├── README.md # Project documentation


---

## 🔧 Requirements

This project uses Python 3.10+ and the following library:

- `cryptography` for ECDSA and secure hash algorithms

Install with:

```bash
pip install cryptography

