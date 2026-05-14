# secure-encrypto v1.0.0

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Security](https://img.shields.io/badge/security-AES--256--GCM-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Status](https://img.shields.io/badge/status-stable-success)

Secure desktop file encryption application using AES-256-GCM and Argon2id.

Created by **infobicho**.

---

# Features

- AES-256-GCM authenticated encryption
- Argon2id password key derivation
- Secure file wiping
- Desktop GUI (Tkinter / CustomTkinter)
- Command-line support
- Streaming encryption for large files
- Password strength analysis
- Automated tests
- GitHub Actions CI

---

# Security

secure-encrypto uses modern cryptographic standards:

| Component | Technology |
|---|---|
| Encryption | AES-256-GCM |
| KDF | Argon2id |
| Authentication | GCM Authentication Tag |
| Randomness | OS CSPRNG |
| Password Generation | Python secrets module |

---

# Installation

```bash
git clone https://github.com/infobicho/secure-encrypto.git
cd secure-encrypto
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
python main.py
```

---

# CLI Usage

```bash
python main.py encrypt file.txt
python main.py decrypt file.enc
python main.py encrypt file.txt -p mypassword
```

---

# Project Structure

```text
secure_encrypto/
├── core/
├── ui/
├── utils/
tests/
.github/workflows/
```

---

# Recommendations

- Use passwords longer than 16 characters
- Store backups securely
- Never reuse passwords
- Keep encrypted backups offline

---

# Warning

Secure wipe cannot guarantee complete deletion on SSD/NVMe devices due to wear leveling.

---

# Release

Current stable release: **v1.0.0**

---

# License

MIT License
