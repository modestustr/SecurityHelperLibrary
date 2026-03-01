# CI/CD Status

Automated testing and security validation for every commit.

## Build & Test Status

> **Latest Release**: v2.1.0 with security hardening, pentest enforcement, and CI/CD governance

| Workflow | Status | Coverage |
|----------|--------|----------|
| **Security Pentest Suite** | [![Security Pentest Suite](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/security-tests.yml/badge.svg)](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/security-tests.yml) | 13 tests across 10 attack vectors |
| **Build & Unit Tests** | [![Build & Test Suite](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/build.yml/badge.svg)](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/build.yml) | Multi-framework (net481, net6.0, net8.0) |
| **Publish** | [![Publish NuGet Package](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/publish.yml/badge.svg)](https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/publish.yml) | Automatic on master push |

---

## Workflow Details

### 1. Security Pentest Suite (`security-tests.yml`)

**Trigger**: Every push/PR (master, development)

**Tests**: 13 comprehensive security tests
- ✅ Argon2 parameter validation (min iterations, min memory)
- ✅ Salt format enforcement (Base64-only)
- ✅ Salt size validation (16-byte minimum)
- ✅ AES-GCM component validation (nonce, tag, ciphertext)
- ✅ Timing attack resistance (FixedTimeEquals)
- ✅ Memory cleanup validation (byte array zeroing)
- ✅ Exception handling robustness (no DoS via malformed input)
- ✅ PBKDF2 integrity (hash generation, verification)
- ✅ HMAC reproducibility
- ✅ RNG entropy validation

**Frameworks**: net481, net6.0, net8.0

**Duration**: ~30 seconds

**Requirement**: Must PASS for merge to master/development

---

### 2. Build & Unit Tests (`build.yml`)

**Trigger**: Every push/PR with code changes (master, development)

**Jobs**:

#### Build Job
- Compile with `/p:TreatWarningsAsErrors=true`
- Run unit tests (excluding pentest category)
- Multi-framework: net6.0, net8.0
- Upload coverage to Codecov
- Duration: ~45 seconds per framework

#### Quality Job  
- StyleCop analyzer checks
- Compiler warning validation
- CHANGELOG.md verification (on PRs)
- Duration: ~30 seconds

#### Package Job
- Generate NuGet package (on push)
- Upload as artifact for review
- Duration: ~20 seconds

**Duration**: ~2 minutes total

**Requirement**: Must PASS for merge to master/development

---

### 3. Publish NuGet Package (`publish.yml`)

**Trigger**: Push to master branch (automatic on version change)

**Steps**:
1. Extract version from `.csproj`
2. Build Release NuGet package
3. Publish to NuGet.org
4. Create GitHub Release
5. Upload package artifact

**NuGet API Key**: Stored in GitHub Secrets (repo admin only)

**Duration**: ~1 minute

**Automatic**: Happens on every master push with version bump

---

## Performance Metrics

### CI/CD Pipeline Speed

```
┌─────────────────────────────────────────────────┐
│ Push to development/master                      │
└─────────────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   Build & Test  Security      Quality
   (45s/frame)    Pentest      Checks
                  (30s)        (30s)
        │             │             │
         └──────────┬──────────┬────┘
                    ▼
            All Passed? ✓ 
                    │
        ┌───────────┴──────────┐
        ▼                      ▼
   Merge OK              Merge BLOCKED
  (on approval)          (fix required)
```

**Total CI/CD Runtime**: ~2 minutes

---

## Branch Protection Rules

### Protected Branch: `master`
- ✅ Must pass: Security Pentest Suite
- ✅ Must pass: Build & Unit Tests
- ✅ Require: 1 code review approval
- ✅ Require: Status checks to pass before merge
- ✅ Dismiss stale PR approvals when new commits push

### Protected Branch: `development`
- ✅ Must pass: Security Pentest Suite
- ✅ Must pass: Build & Unit Tests
- ⚠ Review approval: recommended but not required

---

## Local Validation (Before Push)

Run these locally to validate before pushing:

```bash
# 1. Restore dependencies
dotnet restore

# 2. Build with strict warnings
dotnet build -c Release /p:TreatWarningsAsErrors=true

# 3. Run all tests
dotnet test

# 4. Run pentest suite specifically
dotnet test --filter "Category=Pentest"

# 5. Pack NuGet package (validate)
dotnet pack SecurityHelperLibrary/SecurityHelperLibrary.csproj -c Release -o ./nupkg
```

**Pro Tip**: Create a pre-commit hook to automate this:

```bash
#!/bin/bash
# .git/hooks/pre-commit
dotnet build -c Release /p:TreatWarningsAsErrors=true || exit 1
dotnet test --filter "Category=Pentest" || exit 1
```

---

## Troubleshooting CI/CD Failures

### Build Fails: Compiler Errors

**Solution**:
```bash
dotnet clean
dotnet restore
dotnet build -c Release
```

### Tests Fail: Unit Tests

**Solution**:
```bash
# Run specific test with verbose output
dotnet test --filter "TestName" -v n
```

### Pentest Fails: Security Regression

**Solution**:
1. Review the failing test: `Security*Tests.cs`
2. Identify the vulnerability being flagged
3. Understand why the test is failing
4. Fix the code or update the security parameter (with justification)
5. Push again

### NuGet Publish Fails

**Check**:
- [ ] Version is newer than last published version
- [ ] NuGet API key is valid and has publish permissions
- [ ] Package is not already published with that version

---

## GitHub Secrets

**Set by repo admin** (Settings → Secrets and variables):

| Secret | Purpose | Where Used |
|--------|---------|-----------|
| `NUGET_API_KEY` | Publish to NuGet.org | `publish.yml` |

---

## View Workflow Results

Click badge above or go to:
- Security Pentest: https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/security-tests.yml
- Build & Test: https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/build.yml
- Publish: https://github.com/modestustr/SecurityHelperLibrary/actions/workflows/publish.yml

---

## Contact

For CI/CD questions or issues:
- GitHub Issues: [Report a problem](https://github.com/modestustr/SecurityHelperLibrary/issues)
- Email: ci@modestustr.com

