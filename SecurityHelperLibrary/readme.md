# SecurityHelperLibrary v2.1.2

SecurityHelperLibrary is a production-grade cryptographic helper library for password hashing, message authentication, and authenticated encryption.

Targets:
- `net481`
- `net8.0`

## Highlights

- PBKDF2 with strong defaults and formatted storage payload support.
- Argon2id support with security guardrails (minimums + bounded parallelism).
- AES-GCM encrypt/decrypt APIs on modern targets.
- Fixed-time hash verification behavior to reduce timing leakage.
- Sensitive-buffer cleanup helpers for `byte[]` and `Span<char>`.
- Generic external cryptographic error model with optional internal incident-code logging.

## Install

```bash
dotnet add package SecurityHelperLibrary --version 2.1.2
```

## Quick Start

### PBKDF2 hash + verify

```csharp
using SecurityHelperLibrary;
using System.Security.Cryptography;

ISecurityHelper helper = new SecurityHelper();

string stored = helper.HashPasswordWithPBKDF2(
    "MyPassword123!",
    out string salt,
    HashAlgorithmName.SHA256,
    iterations: 210000,
    hashLength: 32);

bool valid = helper.VerifyPasswordWithPBKDF2("MyPassword123!", stored);
```

### Argon2id hash

```csharp
using SecurityHelperLibrary;

ISecurityHelper helper = new SecurityHelper();

string salt = helper.GenerateSalt();
string argon2Hash = helper.HashPasswordWithArgon2(
    "MyPassword123!",
    salt,
    iterations: 4,
    memoryKb: 131072,
    degreeOfParallelism: 4,
    hashLength: 32);
```

### AES-GCM (supported target)

```csharp
using SecurityHelperLibrary;

ISecurityHelper helper = new SecurityHelper();

byte[] key = helper.GenerateSymmetricKey(32);
string encrypted = helper.EncryptStringGCM("sensitive-value", key);
string decrypted = helper.DecryptStringGCM(encrypted, key);

helper.ClearSensitiveData(key);
```

## Optional incident telemetry

You can provide an internal incident callback while keeping external error messages generic:

```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper(code =>
{
    // Send to logs/SIEM/internal monitoring
    Console.WriteLine($"Security incident: {code}");
});
```

## Security notes

- Use per-user random salt values.
- Keep Argon2/PBKDF2 cost settings high enough for your threat model.
- Store secrets and JWT signing keys in secure configuration providers.
- Clear sensitive buffers when possible.

## License

See [LICENSE.txt](../LICENSE.txt).
