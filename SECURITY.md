# Security Policy

## Reporting Security Vulnerabilities

**DO NOT open a public GitHub issue for security vulnerabilities.**

Security vulnerabilities are handled confidentially and promptly.

### How to Report

1. **GitHub Security Advisory Form** (Recommended):
   - Visit: https://github.com/modestustr/SecurityHelperLibrary/security/advisories
   - Click "Report a vulnerability"
   - Fill in the form with vulnerability details

2. **Email** (For urgent/sensitive issues):
   - security@modestustr.com
   - Include: description, affected versions, proof-of-concept, recommended fix

3. **Responsible Disclosure Timeline**:
   - **Day 0**: Report received
   - **Day 1**: Acknowledgment and initial assessment
   - **Day 3-7**: Security team investigates and develops fix
   - **Day 7-14**: Fix validated internally
   - **Day 14-21**: Coordinated disclosure (vendor notified 7 days before public)
   - **Public Disclosure**: Security advisory released, CVE assigned if applicable

---

## Supported Versions

| Version | Status | Support Until | Security Updates |
|---------|--------|---------------|------------------|
| 2.1.x   | Active | 2028-03-01    | ✅ Yes (Pentest-enforced) |
| 2.0.3   | LTS    | 2027-03-01    | ✅ Critical only |
| < 2.0.0 | EOL    | Unofficial    | ❌ No |

**Note**: Only the latest minor/patch version receives active support. We recommend updating immediately when security releases are published.

---

## Security Enhancements

### Current Security Posture (v2.1.0)

✅ **OWASP Compliance**
- OWASP Top 10 CWE mitigation
- OWASP Password Storage Cheat Sheet
- OWASP Cryptographic Storage Cheat Sheet

✅ **Cryptographic Standards**
- NIST SP 800-132 (PBKDF2 ≥ 210,000 iterations)
- OWASP Argon2id (min 3 iterations, 64MB memory)
- AES-GCM 256-bit (authenticated encryption)
- HMAC-SHA256/384/512

✅ **Security Controls**
- Secure memory clearing (GCHandle pinning + Array.Clear)
- Fixed-time comparison (timing attack resistance)
- Component-level input validation
- Exception handling without information leakage

✅ **Defense-in-Depth**
- Multiple cryptographic algorithms (Argon2, PBKDF2, AES-GCM, HMAC)
- Parameter hardness enforcement via automated tests
- Continuous regression prevention (pentest CI/CD)

### Audit & Testing

- ✅ 13 comprehensive pentest tests (10 attack vectors)
- ✅ Multi-framework testing (net481, net6.0, net8.0)
- ✅ Automated enforcement via GitHub Actions (every PR)
- ✅ Code review by security experts

---

## Known Security Considerations

### 1. .NET Framework 4.8.1 Limitations

- **AES-GCM**: Not available; `NotSupportedException` thrown
  - **Mitigation**: Use .NET 6+ for full AES-GCM support
  - **Alternative**: Use PBKDF2 + HMAC for older frameworks

- **ReadOnlySpan<char>**: Not available for passwords
  - **Mitigation**: String-based APIs available but less secure
  - **Recommendation**: Upgrade to .NET 6+ for sensitive applications

### 2. Password String Immutability

**Issue**: C# strings are immutable; cannot be securely zeroed after use

**Mitigation**:
- Use `ReadOnlySpan<char>` APIs (NET6+) for sensitive operations
- Always call `ClearSensitiveData()` on byte arrays containing passwords
- Don't log or print passwords

**Example**:
```csharp
// ✅ Good: Use Span and clear
ReadOnlySpan<char> password = "MyPassword".AsSpan();
byte[] hash = securityHelper.HashPasswordWithPBKDF2(password, salt, HashAlgorithmName.SHA256);
// Span is stack-allocated and automatically cleared

// ⚠ Okay: String-based, but be careful
string password = "MyPassword";
byte[] hash = securityHelper.HashPasswordWithPBKDF2(password, salt, HashAlgorithmName.SHA256);
// String remains in memory; consider ImmediateDispose patterns
```

### 3. Random Number Generation

- Uses `RandomNumberGenerator.Create()` for salt generation
- Cryptographically secure (OS-backed RNG)
- Performance: ~10µs per 32-byte salt

**Trust**: Depends on OS entropy pool quality (Linux: /dev/urandom, Windows: BCryptGenRandom)

### 4. Timing Attacks

**Mitigation**: 
- Password verification uses `FixedTimeEquals` (constant-time comparison)
- Hash comparison takes equal time regardless of match position

**Limitation**: String hashing operations are NOT constant-time (inherent to algorithm)

---

## Dependencies

### Mandatory
- `.NET Standard 2.0+` or `.NET Framework 4.8.1`
- `System.Security.Cryptography` (builtin)

### Optional
- `Isopoh.Cryptography.Argon2` NuGet package (for Argon2 support)
  - Version: ≥ 2.0.0
  - License: MIT
  - Security: Community-maintained, verified implementation

### Security Updates Policy

We monitor dependencies for vulnerabilities using:
- GitHub Dependabot
- NuGet security advisories
- CVSS scoring for impact assessment

**SLA**: Security patch for critical vulnerabilities within 24 hours of disclosure.

---

## Best Practices When Using This Library

### ✅ Do

1. **Update regularly**: Keep library at latest version
2. **Use strong defaults**: Don't override minimum parameters
3. **Validate inputs**: Verify salt/key formats before passing
4. **Clear sensitive data**: Call `ClearSensitiveData()` explicitly
5. **Use HTTPS**: Encrypt data in transit (library handles at-rest encryption)
6. **Monitor logs**: Don't log passwords or hashes
7. **Use ReadOnlySpan<char>**: For passwords on .NET 6+
8. **Hash passwords**: Use PBKDF2 or Argon2; never store plaintext

### ❌ Don't

1. **Don't reduce parameters**: e.g., `MinArgon2Iterations = 1`
2. **Don't reuse salts**: Generate new salt per password
3. **Don't log exceptions**: Exception messages contain no secrets, but sanitize output
4. **Don't compress encrypted data**: Can leak information (CRIME/BREACH attacks)
5. **Don't encrypt then hash**: Always hash plaintext, then optionally encrypt hash
6. **Don't use hardcoded keys**: Use key vault / secure configuration
7. **Don't trust Base64**: Just because it's encoded doesn't mean it's valid

---

## Vulnerability Disclosure Template

When reporting, try to include:

```markdown
**Title**: [Brief description of vulnerability]

**CVSS Score**: [If known, e.g., 8.6 - High]

**Affected Versions**: [e.g., 2.0.3 and earlier]

**Description**: 
[Technical details of the vulnerability]

**Attack Scenario**:
[How would an attacker exploit this?]

**Proof of Concept**:
[Minimal code that reproduces the issue]

**Impact**:
[What's the security consequence?
 - Confidentiality: Can passwords be leaked?
 - Integrity: Can an attacker forge hashes?
 - Availability: Can this cause denial of service?
]

**Recommended Fix**:
[If you have one]

**References**:
[Related CVEs, papers, or discussions]
```

---

## Security Advisories

View published advisories:
- GitHub: https://github.com/modestustr/SecurityHelperLibrary/security/advisories
- NVD: https://nvd.nist.gov/ (search "SecurityHelperLibrary")

---

## FAQ

**Q: Is this library suitable for production?**
A: Yes. v2.1.0 meets banking/finance/healthcare-grade security standards with active pentest enforcement.

**Q: Can I use this with legacy .NET Framework 4.6.1?**
A: No. Minimum is .NET Framework 4.8.1 for modern cryptographic APIs.

**Q: What if there's a security finding in Argon2 library?**
A: We monitor `Isopoh.Cryptography.Argon2` for CVEs and will patch immediately if critical.

**Q: Should I pin a specific version?**
A: Lock to MINOR version (e.g., `2.1.*`) to receive security patches while avoiding breaking changes.

**Q: How do I verify the integrity of downloads?**
A: NuGet packages are signed. Verify using: `dotnet nuget verify`

---

## Contact

- **Security Reports**: security@modestusnet.com
- **GitHub Issues**: Bug reports (non-security): https://github.com/modestustr/SecurityHelperLibrary/issues
- **Discussions**: Architecture/design: https://github.com/modestustr/SecurityHelperLibrary/discussions

---

**Last Updated**: March 1, 2026
**Next Review**: September 1, 2026

