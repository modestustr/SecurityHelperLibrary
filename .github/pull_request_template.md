## 🔒 Security PR Checklist

**Type of Change** (select one):
- [ ] 🔐 Security hardening / vulnerability fix
- [ ] ✨ Feature addition
- [ ] 🐛 Bug fix
- [ ] 📖 Documentation
- [ ] 🔧 Refactoring / code improvement

---

## 📋 Description

**What does this PR do?**
<!-- Provide a clear description of the changes -->

**Why is this change needed?**
<!-- Explain the motivation or problem this solves -->

**Related Issues**
<!-- Link to related issues: Fixes #123, Related to #456 -->

---

## ✅ Security Validation

- [ ] **Pentest Suite Passes**: All `dotnet test --filter "Category=Pentest"` tests pass
  ```bash
  dotnet test SecurityHelperLibrary.Tests/SecurityHelperLibrary.Tests.csproj --filter "Category=Pentest"
  ```
- [ ] **No Security Regression**: Changes don't weaken existing security controls
- [ ] **Input Validation**: All new inputs are validated before use
- [ ] **Memory Safety**: Sensitive data (passwords, keys) are properly cleared after use
- [ ] **Cryptographic Parameters**: Argon2/PBKDF2 meet minimum hardness thresholds
  - Argon2: Min 3 iterations, min 64MB memory
  - PBKDF2: Min 210,000 iterations
- [ ] **Timing Attack Prevention**: Password verification uses fixed-time comparison

---

## 🧪 Testing

- [ ] **Unit Tests Added/Updated**: Existing tests still pass, new functionality has test coverage
- [ ] **Framework Coverage**: Tested on both `net481` and `net8.0`
  ```bash
  dotnet build -c Release
  dotnet test -c Release
  ```
- [ ] **Pentest Category Tests**: Any new cryptographic methods have pentest coverage
- [ ] **No Breaking Changes**: Public API is backward-compatible (unless MAJOR version bump)

---

## 📝 Code Quality

- [ ] **Code follows C# conventions**: Consistent style with existing codebase
- [ ] **No compiler warnings**: Build runs cleanly with `/WarnAsError`
- [ ] **Documentation updated**: XML comments added for public methods
- [ ] **CHANGELOG.md updated**: Entry added describing the change
- [ ] **RELEASE_NOTES.md updated** (if feature/security change): Summary added for users

---

## 🔎 Reviewer Guidance

**Key areas to review:**
- [ ] Cryptographic correctness (if applicable)
- [ ] Secure memory handling (GCHandle pinning, Array.Clear usage)
- [ ] Exception handling (no information leakage in error messages)
- [ ] Parameter validation (early/explicit validation per component)

**Test Results Board:**
- [ ] GitHub Actions: Security Pentest Suite ✓ PASSED
- [ ] GitHub Actions: Build & Unit Tests ✓ PASSED
- [ ] Local: `dotnet test SecurityHelperLibrary.Tests` ✓ PASSED

---

## 📦 Deployment Notes

**Version Bump** (if applicable):
- [ ] Patch (2.0.x): Bug fixes, security patches only
- [ ] Minor (2.1.0): New features, security enhancements
- [ ] Major (3.0.0): Breaking API changes

**NuGet Package**:
- [ ] Version updated in `.csproj`
- [ ] Package will auto-publish via GitHub Actions on merge to master

---

**Remember**: This library is used in banking/finance/healthcare systems. Security comes first. 🔐
