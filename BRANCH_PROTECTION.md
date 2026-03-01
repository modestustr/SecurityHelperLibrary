# Branch Protection Rules

This document describes the automated protection rules for SecurityHelperLibrary repository branches.

## Protected Branches

### `master`
- **Purpose**: Production release branch
- **Requirements**:
  - ✅ All GitHub Actions CI/CD workflows must pass (Build, Security Pentest Suite)
  - ✅ At least 1 code review approval required
  - ✅ All conversations must be resolved
  - ✅ Commits must be signed (recommended)
  - ✅ Latest commit from PR branch must be approved

### `development`
- **Purpose**: Integration branch for features and fixes
- **Requirements**:
  - ✅ All GitHub Actions CI/CD workflows must pass (Build, Security Pentest Suite)
  - ✅ At least 1 code review approval recommended
  - ⚠ Allows force push (for maintainers to clean up commits)

---

## Automated Checks (GitHub Actions)

### 1. Security Pentest Suite (`security-tests.yml`)
**Runs on**: Every push/PR (master, development)
**Tests**: 13 comprehensive security tests across 10 attack vectors
**Requirements**:
- Argon2 parameter validation (min iterations, memory)
- Salt format enforcement (Base64-only)
- AES-GCM component validation
- Timing attack resistance (FixedTimeEquals)
- Memory cleanup validation
- **Status**: Must PASS ✓

### 2. Build & Unit Tests (`build.yml`)
**Runs on**: Every push/PR (master, development) with code changes
**Tests**: Multi-framework (net6.0, net8.0)
**Includes**:
- Compilation with `/p:TreatWarningsAsErrors=true`
- Unit tests (excluding pentest category)
- Code quality checks
- StyleCop analysis
- CHANGELOG.md validation (on PRs)
- Package generation (on push to master/development)
**Status**: Must PASS ✓

---

## Manual Approvals

### Code Review Requirements

#### For Security Changes
- [ ] Cryptography expert review
- [ ] Memory safety audit
- [ ] Parameter hardness validation
- [ ] Exception handling review
- Minimum: 2 approvals

#### For Feature Additions
- [ ] Functionality review
- [ ] API design review
- [ ] Test coverage >80%
- [ ] Documentation complete
- Minimum: 1 approval

#### For Bug Fixes
- [ ] Root cause identified
- [ ] Fix validated
- [ ] Regression tests added
- Minimum: 1 approval

---

## Merging to `master` (Release)

```
development → PR to master → CI/CD ✓ → Review ✓ → Merge to master
```

**Triggers on `master` merge**:
1. GitHub Actions: Build & Test Suite completes
2. GitHub Actions: Security Pentest Suite completes
3. NuGet package auto-publishes to nuget.org (if version bumped)

---

## Bypassing Protection (Emergency Only)

**Only repo admins can dismiss branch protections.**

Requires:
1. Document reason in issue/PR
2. Post-merge: add regression test
3. Add entry to CHANGELOG.md
4. Review for security impact

---

## Related Documents

- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
- [Security Policy](SECURITY.md) - How to report security issues
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [RELEASE_NOTES.md](RELEASE_NOTES.md) - User-facing changes

