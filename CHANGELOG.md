# Changelog

All notable changes to this project will be documented in this file.

## [2.1.1] - 2026-03-01
- Fix: Make `RateLimiter.IsAllowed()` deterministic and thread-safe under concurrent requests.
- Fix: Restore AES-GCM empty-plaintext round-trip compatibility in `DecryptStringGCM()`.
- CI: Stabilize packaging on GitHub Actions for multi-target output (`net481` + `net8.0`).
- CI: Prevent duplicate publish race conditions and tolerate already-published packages via `--skip-duplicate`.
- CI: Add publish workflow permission (`contents: write`) required for GitHub Release creation.
- Docs: Update README and release notes to reflect `2.1.1` changes and supported frameworks.

## [2.1.0] - 2026-03-01
- Security: Strengthen Argon2 minimum parameters — `MinArgon2Iterations: 2→3`, `MinArgon2MemoryKb: 32768→65536` (32MB→64MB) to increase resistance against hardware-accelerated dictionary attacks.
- Security: Eliminate `GetSaltBytes()` UTF-8 fallback — enforce Base64-only salt format to prevent format-confusion bypass attacks.
- Security: Enhance `DecryptStringGCM()` with component-level Base64 validation (nonce, tag, ciphertext) and guaranteed memory cleanup via `finally` block with `SecureZeroMemory()`.
- Security: Implement `SecureZeroMemory()` method using `GCHandle.Alloc(pinned)` + `Array.Clear()` + `Marshal.WriteByte()` to prevent JIT compiler optimization bypass of sensitive memory clearing.
- Chore: Add GitHub Actions CI/CD workflow (`security-tests.yml`) for automated pentest suite execution on every PR and push to enforce security regression prevention across all target frameworks.
- Note: All changes are backward-compatible. No public API breaking changes.

## [2.0.3] - 2026-03-01
- Fix: harden PBKDF2 verification with dynamic hash length,Fix: tighten AES-GCM decrypt validation for nonce/tag sizes,Security: clear Argon2 password bytes after hashing,Chore: simplify async wrappers and improve robustness

## [2.0.2] - 2026-02-16
- Security: Increase default PBKDF2 iterations from `100000` to `210000`.
- Security: Strengthen default Argon2 parameters (`iterations=4`, `memoryKb=131072`, `degreeOfParallelism=4`).
- Security: Add parameter validation guards for PBKDF2/Argon2 and minimum salt/hash sizes.
- Fix: Improve Argon2 salt handling by accepting Base64 salt input when provided.
- Chore: Bump package version to `2.0.2`.

## [2.0.1] - 2026-02-02
- Fix: Use explicit `AesGcm` constructor with 16-byte tag to address obsolescence warnings on .NET 8.
- Fix: Add `RandomNumberGenerator` fallback for frameworks older than .NET 6 (`Create().GetBytes`) to support .NET Framework targets.
- Fix: Replace C# 8+ language constructs (using-declaration, switch-expression, recursive patterns) with C# 7.3-compatible constructs so `net481` builds cleanly.
- Fix: Add project-local `FixedTimeEquals` helper for targets that lack `CryptographicOperations.FixedTimeEquals`.
- Chore: Improve disposal patterns (using blocks / try/finally) for disposable crypto types.
- Chore: Bump package version to `2.0.1` for release branch.

Notes:
- These changes are backward-compatible and focused on cross-target compatibility and warnings cleanup. No public API breaking changes are intended.

