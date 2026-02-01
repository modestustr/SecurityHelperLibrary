# SecurityHelperLibrary

Version: 2.0.0

SecurityHelperLibrary is a small, focused cryptographic helper library that provides hashing, PBKDF2 and Argon2 password hashing, HMAC computation, and AES-GCM authenticated encryption. This release (2.0.0) introduces safer in-memory password handling via Span-based APIs, conditional AES-GCM support for modern runtimes, and a comprehensive test suite.

## Highlights (v2.0.0)

- Major version bump due to public API additions to `ISecurityHelper` (breaking change).
- Added Span-based secure APIs for password hashing and verification (NET6.0+).
- Added memory-clearing helpers for sensitive data.
- Conditional AES-GCM implementation available on .NET 6+.
- Comprehensive xUnit test project covering hashing, HMAC, PBKDF2, Argon2, AES-GCM, and secure-span methods.

## Breaking Changes

The `ISecurityHelper` interface has been extended with new public methods. Any custom implementations of `ISecurityHelper` must implement the new methods or update to reference this v2.0.0 implementation.

New or changed public surface (high level):

- `HashPasswordWithPBKDF2Span(ReadOnlySpan<char> password, byte[] salt, ...)` (NET6.0+)
- `VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char> password, string storedHashString)` (NET6.0+)
- `ClearSensitiveData(Span<char> data)` (NET6.0+)
- `ClearSensitiveData(byte[] data)`
- AES-GCM methods are present but only active on .NET 6+ (older targets will throw `NotSupportedException`).

## Quick Start

Install from NuGet (when published):

```bash
dotnet add package SecurityHelperLibrary --version 2.0.0
```

Basic usage (example):

```csharp
using SecurityHelperLibrary;
using System.Security.Cryptography;

ISecurityHelper helper = new SecurityHelper();

// Hash a password with PBKDF2 (auto-generated salt)
string stored = helper.HashPasswordWithPBKDF2("MyPassword", out string salt, HashAlgorithmName.SHA256);

// Verify
bool ok = helper.VerifyPasswordWithPBKDF2("MyPassword", stored);

// For more secure in-memory handling (NET6+)
ReadOnlySpan<char> pwdSpan = "MyPassword".AsSpan();
byte[] saltBytes = Convert.FromBase64String(helper.GenerateSalt());
string hash = helper.HashPasswordWithPBKDF2Span(pwdSpan, saltBytes, HashAlgorithmName.SHA256);

// AES-GCM (NET6+)
byte[] key = helper.GenerateSymmetricKey();
string encrypted = helper.EncryptStringGCM("Sensitive data", key);
string decrypted = helper.DecryptStringGCM(encrypted, key);
```

## Running Tests

The repository includes an xUnit test project. Run tests for all targets with:

```bash
dotnet test
```

To run for a specific target/framework:

```bash
dotnet test -f net8.0    # Run tests targeting .NET 8
dotnet test -f net481    # Run tests targeting .NET Framework 4.8.1
```

## Build

Build the solution:

```bash
dotnet build
```

## Migration Notes

- If you maintain a custom `ISecurityHelper` implementation, add the new methods or switch to the provided `SecurityHelper` implementation.
- AES-GCM is only functional on .NET 6+; on older frameworks the AES-GCM methods will throw `NotSupportedException`.

## Security Notes

- Use the Span-based APIs when possible to reduce sensitive data exposure on the managed heap.
- Always clear sensitive buffers after use via `ClearSensitiveData`.
- The library uses fixed-time comparisons to mitigate timing attacks.

## Project Structure

```
SecurityHelperLibrary/
├── SecurityHelperLibrary/          # main library
├── SecurityHelperLibrary.Tests/    # xUnit tests
├── nuget-packages/                 # built packages
└── README.md
```

## Release Notes

See `RELEASE_NOTES.md` for more details about this release.

---

Last updated: February 1, 2026