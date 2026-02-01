# Release Notes - SecurityHelperLibrary 2.0.0

## Overview
This release introduces major API additions and security improvements. Because the `ISecurityHelper` interface was extended with new public methods, this is a breaking change and the major version has been bumped to `2.0.0`.

## Highlights
- Added secure Span-based APIs for password hashing and verification (NET6.0+):
  - `HashPasswordWithPBKDF2Span(ReadOnlySpan<char>, ...)`
  - `VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char>, ...)`
- Added memory-clearing helper methods:
  - `ClearSensitiveData(byte[])`
  - `ClearSensitiveData(Span<char>)` (NET6.0+)
- Conditional AES-GCM support (available on .NET 6+ via `AesGcm`; falls back to NotSupported on .NET Framework)
- Comprehensive unit test project `SecurityHelperLibrary.Tests` (xUnit) covering hashing, HMAC, PBKDF2, Argon2, AES-GCM, and secure-span methods.

## Breaking Changes
- `ISecurityHelper` interface has new public methods. Any existing implementations must be updated to compile against `2.0.0`.

## Migration
- Implement new interface methods in custom `ISecurityHelper` implementations or update to use the provided `SecurityHelper` implementation.
- If you need to remain on the previous API, continue using `1.x` series.

## Notes
- Multi-targeting: `net481;net8.0`.
- AES-GCM requires .NET 6+; on older frameworks the AES-GCM methods will throw `NotSupportedException`.

**Release date:** February 1, 2026
