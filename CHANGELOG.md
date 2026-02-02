# Changelog

All notable changes to this project will be documented in this file.

## [2.0.1] - 2026-02-02
- Fix: Use explicit `AesGcm` constructor with 16-byte tag to address obsolescence warnings on .NET 8.
- Fix: Add `RandomNumberGenerator` fallback for frameworks older than .NET 6 (`Create().GetBytes`) to support .NET Framework targets.
- Fix: Replace C# 8+ language constructs (using-declaration, switch-expression, recursive patterns) with C# 7.3-compatible constructs so `net481` builds cleanly.
- Fix: Add project-local `FixedTimeEquals` helper for targets that lack `CryptographicOperations.FixedTimeEquals`.
- Chore: Improve disposal patterns (using blocks / try/finally) for disposable crypto types.
- Chore: Bump package version to `2.0.1` for release branch.

Notes:
- These changes are backward-compatible and focused on cross-target compatibility and warnings cleanup. No public API breaking changes are intended.
