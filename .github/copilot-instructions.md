# GitHub Copilot Agent Instructions — SecurityHelperLibrary

## Project Overview

SecurityHelperLibrary is a production-grade cryptographic utility library for .NET.  
It is used in **banking, finance, and healthcare systems** where a single security regression can have critical consequences.

Supported targets: `net481` (legacy) and `net8.0` (modern).  
NuGet package: [`SecurityHelperLibrary`](https://www.nuget.org/packages/SecurityHelperLibrary/)

---

## Agent Responsibilities

When working in this repository, the GitHub Copilot agent must:

1. **Understand the security-critical nature** of every change. This is a cryptographic library — mistakes can silently weaken security for all downstream consumers.
2. **Maintain backward compatibility** of the public `ISecurityHelper` interface unless a major version bump is explicitly planned.
3. **Preserve multi-target support** (`net481` + `net8.0`). Any `net8.0`-only API must be wrapped in `#if NET6_0_OR_GREATER` conditional compilation.
4. **Run tests on both targets** before considering a change complete.
5. **Update documentation** (`CHANGELOG.md`, `RELEASE_NOTES.md`, XML doc-comments) alongside code changes.
6. **Never commit secrets** (API keys, credentials, private keys) to the repository.

---

## How to Build and Test

### Restore and build

```bash
dotnet restore
dotnet build -c Release /p:TreatWarningsAsErrors=true
```

### Run unit tests (non-pentest)

```bash
dotnet test SecurityHelperLibrary.Tests/SecurityHelperLibrary.Tests.csproj \
  -c Release \
  --filter "Category!=Pentest"
```

### Run the security pentest suite

```bash
dotnet test SecurityHelperLibrary.Tests/SecurityHelperLibrary.Tests.csproj \
  --filter "Category=Pentest" \
  -f net8.0 \
  -c Release
```

### Run the complete test suite

```bash
dotnet test -c Release
```

All tests must pass on both `net8.0` and `net481` before any change is merged.

---

## Project Structure

```
SecurityHelperLibrary/
├── SecurityHelperLibrary/           # Main library (ISecurityHelper + SecurityHelper)
├── SecurityHelperLibrary.Tests/     # xUnit tests (unit + pentest categories)
├── SecurityHelperLibrary.Sample/    # Sample ASP.NET Core app using the library
├── .github/
│   ├── workflows/                   # CI/CD: build.yml, security-tests.yml, publish.yml
│   ├── ISSUE_TEMPLATE/
│   └── pull_request_template.md
├── scripts/                         # Release automation scripts
├── CHANGELOG.md                     # Version history
├── RELEASE_NOTES.md                 # User-facing release notes
├── SECURITY.md                      # Vulnerability reporting policy
└── CONTRIBUTING.md                  # Contributor guidelines
```

---

## Security Rules (Non-Negotiable)

The agent must enforce the following rules on every change:

### Cryptographic Minimums
| Algorithm | Minimum | Reason |
|-----------|---------|--------|
| Argon2id iterations | 3 | OWASP Password Storage Cheat Sheet |
| Argon2id memory | 64 MB (65536 KB) | GPU/ASIC attack resistance |
| Argon2id parallelism | 1–64 | Resource exhaustion guard |
| PBKDF2 iterations | 210 000 | NIST SP 800-132 |
| Salt size | 16 bytes minimum | Collision avoidance |
| Hash length | 16 bytes minimum | Security margin |

### Memory Safety
- Always clear sensitive buffers (passwords, keys) using `ClearSensitiveData()` or `Array.Clear()` in a `finally` block.
- Use `GCHandle.Alloc(data, GCHandleType.Pinned)` for sensitive arrays to prevent relocation by the GC before zeroing.
- Prefer `ReadOnlySpan<char>` for passwords on .NET 6+.

### Error Handling
- Public API must surface **generic** error messages (e.g., `"Invalid security parameters"`) to callers.
- Internal details (incident codes, stack traces) must be passed to the `securityIncidentLogger` callback only — never included in exceptions thrown to callers.

### Timing Attack Prevention
- Password and hash verification must use fixed-time comparison. Do not use `==` or `string.Equals` for comparing cryptographic values.

---

## Code Conventions

- **C# naming**: PascalCase for public members, camelCase for locals and parameters.
- **XML documentation**: All public methods and interfaces must have `<summary>`, `<param>`, and `<returns>` tags.
- **No compiler warnings**: The build runs with `/p:TreatWarningsAsErrors=true`.
- **Single responsibility**: Keep methods focused; aim for ≤ 100 lines per method.
- **Pentest test trait**: Any test covering an attack vector must carry `[Trait("Category", "Pentest")]`.

---

## Commit and Branch Conventions

### Branch naming
- `feature/<description>` — new functionality
- `fix/<description>` — bug fixes
- `security/<description>` — security hardening
- `docs/<description>` — documentation only
- `release/<version>` — release preparation (e.g., `release/2.2.0`)

### Commit message format

```
<type>(<scope>): <subject>

<body>
```

Types: `feat`, `fix`, `security`, `refactor`, `docs`, `test`, `chore`  
Scopes: `crypto`, `memory`, `api`, `tests`, `ci`, `docs`

### Protected branches
- `master` — requires pentest suite + build + code review approval before merge.
- `development` — requires build + pentest pass; code review recommended.

---

## CI/CD Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `build.yml` | push/PR to `master`, `development` | Build, unit tests, quality checks, NuGet packaging |
| `security-tests.yml` | push/PR to `master`, `development` | Pentest suite on `net8.0` |
| `security-guardrails.yml` | push/PR to `master`, `development` | Gitleaks secret scan, dependency review |
| `publish.yml` | manual / tag | Pack and publish NuGet package |

Both `build` and `security-tests` status checks **must pass** before a PR can be merged to `master`.

---

## What the Agent Should NOT Do

- Do **not** weaken cryptographic parameters (lower iterations, smaller memory, shorter salts).
- Do **not** expose internal error details in public-facing exceptions.
- Do **not** introduce non-constant-time comparisons for cryptographic values.
- Do **not** add `#pragma warning disable` to silence security-relevant warnings.
- Do **not** publish or hard-code secrets (NuGet API key, signing certificates, etc.).
- Do **not** remove or skip existing pentest tests.
- Do **not** break the `net481` build when working on `net8.0`-specific features.

---

## Reporting Security Issues

Security vulnerabilities must **not** be reported as public GitHub Issues.

- **Email**: security@modestusnet.com
- **GitHub Security Advisories**: https://github.com/modestustr/SecurityHelperLibrary/security/advisories

---

## Quick Reference

```bash
# Build
dotnet build -c Release /p:TreatWarningsAsErrors=true

# All tests
dotnet test -c Release

# Pentest only
dotnet test SecurityHelperLibrary.Tests/SecurityHelperLibrary.Tests.csproj --filter "Category=Pentest" -f net8.0 -c Release

# Release prep (from a release/x.y.z branch)
.\scripts\release.bat -Changes "Security: ..." "Fix: ..."
```
