# SecurityHelperLibrary v2.0.0

A comprehensive C# library for secure password hashing, symmetric encryption, and cryptographic operations.
**Multi-targeted** for .NET Framework 4.8.1 and .NET 8.0, with modern secure-memory APIs and conditional AES-GCM support.

## Features (v2.0.0)

- PBKDF2 Hashing (SHA256, SHA384, SHA512)
- Argon2 Hashing (Argon2id)
- HMAC Generation (SHA256, SHA384, SHA512)
- AES-GCM Encryption (.NET 6+)
- Span-based Secure APIs (low-alloc)
- Secure Memory Clearing
- Fixed-Time Comparison
- Multi-framework Support (net481, net8.0)

## Breaking Changes in v2.0.0

- ISecurityHelper interface now includes new methods
- AES-GCM methods throw NotSupportedException on .NET Framework 4.8.1
- Added required parameter iterationCount to PBKDF2 methods

## Installation

```bash
dotnet add package SecurityHelperLibrary
```
