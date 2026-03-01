# Contributing to SecurityHelperLibrary

Thank you for your interest in contributing! This document provides guidelines for participating in the project.

## 🔒 Security First

This library is used in banking, finance, and healthcare systems. **Security is our top priority.**

### Security Issues
**DO NOT** open a public GitHub issue for security vulnerabilities. Instead:
1. Email: security@modestustr.com
2. Or visit: [GitHub Security Advisory](https://github.com/modestustr/SecurityHelperLibrary/security/advisories)

Security reports are handled confidentially and promptly.

---

## Code of Conduct

Be respectful, inclusive, and professional. Harassment or discrimination is not tolerated.

---

## Getting Started

### Prerequisites
- .NET SDK 6.0+ (to work with all target frameworks)
- Git
- Visual Studio Code or Visual Studio 2022

### Local Setup

```bash
# Clone the repository
git clone https://github.com/modestustr/SecurityHelperLibrary.git
cd SecurityHelperLibrary

# Restore dependencies
dotnet restore

# Build the entire solution
dotnet build -c Release

# Run all tests (including pentest suite)
dotnet test

# Run only pentest suite
dotnet test --filter "Category=Pentest"
```

---

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bug
```

**Branch naming**:
- `feature/add-xchacha20-support`
- `fix/argon2-crash-on-null-salt`
- `security/increase-pbkdf2-iterations`
- `docs/update-readme`

### 2. Make Changes

#### Code Style
- Follow C# conventions (PascalCase for public members, camelCase for locals)
- Use meaningful variable names
- Keep methods focused on single responsibility
- Max 100 lines per method (guidelines, not absolute)

#### Cryptographic Code
- Document security assumptions clearly
- Reference NIST/OWASP standards
- Include the attack vector being mitigated
- Explain parameter choices (e.g., why 3 iterations minimum for Argon2)

Example:
```csharp
/// <summary>
/// Hashes a password using Argon2id with hardened parameters.
/// Mitigates: GPU/ASIC dictionary attacks via high iteration/memory cost.
/// Reference: OWASP Password Storage Cheat Sheet
/// </summary>
public string HashPasswordWithArgon2(string password, string salt)
{
    // Minimum 3 iterations (cost multiplier) per OWASP guidelines
    // Minimum 64MB memory (effective for modern GPUs)
    ...
}
```

#### Memory Safety
- Always zero sensitive data after use:
  ```csharp
  byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
  try
  {
      // Use passwordBytes...
  }
  finally
  {
      ClearSensitiveData(passwordBytes);
  }
  ```
- Use `GCHandle.Alloc(pinned)` for sensitive arrays
- Consider using `ReadOnlySpan<char>` for passwords (NET6+)

#### Testing
- Write tests BEFORE implementing features (TDD)
- Tests must pass on both `net481` and `net8.0`
- Pentest tests must be marked with `[Trait("Category", "Pentest")]`
- Use conditional compilation for framework-specific features:
  ```csharp
  #if NET6_0_OR_GREATER
  [Fact]
  public void MyNet6Feature() { }
  #endif
  ```

### 3. Validate Locally

```bash
# Build in Release mode (strict warnings)
dotnet build -c Release /p:TreatWarningsAsErrors=true

# Run unit tests
dotnet test SecurityHelperLibrary.Tests -c Release

# Run pentest suite specifically
dotnet test SecurityHelperLibrary.Tests --filter "Category=Pentest" -c Release
```

All tests must pass before pushing.

### 4. Update Documentation

- [ ] **Code comments**: Add XML documentation for public members
- [ ] **CHANGELOG.md**: Add entry in format:
  ```markdown
  ## [2.1.x] - YYYY-MM-DD
  - Security: [description]
  - Fix: [description]
  - Feature: [description]
  ```
- [ ] **RELEASE_NOTES.md**: Add user-facing explanation if feature/breaking change
- [ ] **README.md**: Update if public API changes
- [ ] **Tests**: Add or update tests

### 5. Commit

```bash
# Clear, descriptive commits
git commit -m "feat: add Argon2 salt validation

- Add validation for minimum 16-byte raw salt length
- Reject UTF-8 salt format (Base64-only now)
- Add test coverage (4 new test cases)
- Update CHANGELOG.md"
```

**Commit message format**:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `security`, `refactor`, `docs`, `test`, `chore`

Scopes: `crypto`, `memory`, `api`, `tests`, `ci`, `docs`

### 6. Push and Create PR

```bash
git push origin feature/my-feature
```

**Go to GitHub and create a Pull Request.**

---

## Pull Request Process

### PR Checklist
See [.github/pull_request_template.md](.github/pull_request_template.md) for full checklist.

**Key requirements**:
- ✅ All GitHub Actions workflows pass
- ✅ Pentest suite passes: `dotnet test --filter "Category=Pentest"`
- ✅ No compiler warnings
- ✅ Unit test coverage for new code
- ✅ CHANGELOG.md updated
- ✅ Code review approved

### Review Process

1. **Automated Checks** (GitHub Actions):
   - Build & Unit Tests (`build.yml`)
   - Security Pentest Suite (`security-tests.yml`)

2. **Code Review** (Maintainers):
   - Security audit (if cryptography-related)
   - API design review
   - Test coverage validation
   - Documentation completeness

3. **Merge**:
   - Once approved and all checks pass
   - Squash-and-merge (for cleaner history)
   - Delete feature branch

---

## Security Enhancements

### Proposing Security Hardening

1. **Research**: Reference NIST, OWASP, academic papers
2. **Test**: Create pentest tests BEFORE implementing
3. **Impact Analysis**: How does this affect performance? API compatibility?
4. **Documentation**: Explain the threat model and mitigation

Example: Argon2 parameter hardening
```
Problem: Current Argon2 (2 iterations, 32MB) vulnerable to GPU/ASIC attacks
Solution: Increase to 3 iterations, 64MB minimum
Impact: +~50ms hashing time, 128× attack difficulty
Tests: TestArgon2MinimumIterationsEnforced, TestArgon2MinimumMemoryEnforced
Reference: OWASP Password Storage Cheat Sheet v3.1
```

### Adding New Attack Vector Tests

1. Create test in `SecurityHelperPentestTests.cs`
2. Mark with `[Trait("Category", "Pentest")]`
3. Use descriptive test names: `TestXXXMinimumParametersEnforced`
4. Document the attack vector in test comments

```csharp
[Fact]
[Trait("Category", "Pentest")]
public void TestArgon2MinimumMemoryEnforced()
{
    // Mitigates: GPU/ASIC dictionary attacks via memory-hard algorithm
    // Attack: Attacker uses hardware accelerators to test millions of passwords
    // Defense: Argon2 with minimum 64MB memory makes acceleration infeasible
    
    string password = "TestPassword";
    string salt = _securityHelper.GenerateSalt();
    
    // Attempt with below-minimum memory (should be rejected or use minimum)
    // ...
}
```

---

## Performance Impact

When submitting performance-sensitive changes:

```bash
# Run perf benchmarks (if available)
dotnet run -c Release -p SecurityHelperLibrary.Benchmarks
```

- [ ] No more than 5% regression in hash operations
- [ ] Document any intentional slowdown (e.g., higher Argon2 cost = security benefit)

---

## Version Bumping

Follow [Semantic Versioning](https://semver.org/):

- **PATCH** (2.0.4): Bug fixes, security patches, no API changes
- **MINOR** (2.1.0): New features, security enhancements, backward-compatible
- **MAJOR** (3.0.0): Breaking API changes

Update version in:
1. `SecurityHelperLibrary/SecurityHelperLibrary.csproj`
2. `CHANGELOG.md`
3. `RELEASE_NOTES.md`

---

## Release Process

(Admin only)

1. Create PR: "Release: 2.1.0"
   - Version bumped in `.csproj`
   - CHANGELOG.md finalized
   - RELEASE_NOTES.md updated
2. Merge to `master` when all checks pass
3. GitHub Actions automatically:
   - Builds package
   - Publishes to NuGet.org
   - Creates GitHub Release

---

## Questions?

- Open a GitHub Discussion for architecture/design questions
- Open an Issue for bugs or feature requests
- Email maintainers for urgent security concerns

---

## Thank You! 🙏

Your contributions help keep this library secure and reliable.

