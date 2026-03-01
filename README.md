# SecurityHelperLibrary

Version: 2.1.0 | [![Security Pentest Suite](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/security-tests.yml/badge.svg)](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/security-tests.yml) | [![Build & Test Suite](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/build.yml/badge.svg)](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/build.yml)

SecurityHelperLibrary is a production-grade cryptographic helper library providing secure password hashing (PBKDF2, Argon2id), HMAC computation, and AES-GCM authenticated encryption. **v2.1.0** brings enterprise-grade security hardening with automated pentest enforcement and comprehensive CI/CD governance.

## Latest Changes (v2.1.0)

- **Argon2 Hardening**: Increased minimum iterations (2→3) and memory (32MB→64MB) = 128× attack cost
- **Secure Memory**: New `SecureZeroMemory()` method with GCHandle pinning for sensitive data cleanup
- **Salt Fortress**: Eliminated UTF-8 fallback, enforcing Base64-only format for strict validation
- **Pentest Enforcement**: 13-test security suite validates 10 attack vectors on every commit
- **CI/CD Governance**: GitHub Actions workflows (security-tests, build, quality, publish) with auto-deploy to NuGet
- **Branch Protection**: Master branch requires pentest + build pass before merge

### Also Included in Recent Releases

**v2.0.1**
- Updated AES-GCM constructor usage to remove .NET 8 obsolescence warnings.
- Improved cross-target compatibility for `net481` and `net8.0`.
- Added fixed-time comparison fallback and disposal cleanups.

For full per-version details, see:
- `CHANGELOG.md`
- `RELEASE_NOTES.md`

## Highlights (v2.0.2)

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
dotnet add package SecurityHelperLibrary --version 2.0.2
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

## Release Workflow (Automated)

Use the release prep script on a matching release branch to keep versioning and changelog updates consistent.

1. Create/switch to a release branch matching the target version:

```bash
git checkout -b release/2.0.3 master
```

2. Run automated release preparation:

```powershell
.\scripts\release.bat -Changes "Security: increase ..." "Fix: improve ..."
```

`Version` is auto-detected from the branch name (for example, `release/2.0.3`).

Optional dry-run:

```powershell
.\scripts\release.bat -Changes "Test: preview" -DryRun
```

This updates:
- `SecurityHelperLibrary/SecurityHelperLibrary.csproj` (`<Version>`)
- `CHANGELOG.md` (new version section)

For process rules and branch naming conventions, see `BRANCHING_POLICY.md`.

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

See `CHANGELOG.md` and `RELEASE_NOTES.md` for version-by-version details.

---

Last updated: February 16, 2026