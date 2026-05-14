# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |

## Reporting a Vulnerability

If you discover a security issue:

1. Do not publish it publicly immediately
2. Contact the maintainer first
3. Provide reproduction steps
4. Wait for confirmation before disclosure

## Cryptography

secure-encrypto uses:

- AES-256-GCM
- Argon2id
- Secure random generation from the operating system

The project avoids deprecated algorithms such as:
- MD5
- SHA1 for password hashing
- ECB mode