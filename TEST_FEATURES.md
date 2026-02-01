# SecurityHelperLibrary - Unit Tests and Secure String Handling

## 🆕 New Features

### 1. Comprehensive Unit Tests

The `SecurityHelperLibrary.Tests` project contains 50+ unit tests covering all SecurityHelper methods:

#### Test Categories:

**Hash Tests:**
- `ComputeHash` - SHA256, SHA384, SHA512 algorithms
- `GenerateSalt` - Random salt generation
- Different input/salt combinations

**PBKDF2 Tests:**
- `HashPasswordWithPBKDF2` - With fixed and random salt
- `VerifyPasswordWithPBKDF2` - Correct/incorrect password comparison
- Format validation and error handling

**AES-GCM Tests (.NET 6.0+):**
- `EncryptStringGCM` / `DecryptStringGCM` - Round-trip test
- Nonce randomness and ciphertext validation
- Modified ciphertext detection

**HMAC Tests:**
- Deterministic computation
- Different key produces different result

**Argon2 Tests:**
- Basic hashing and verification
- Consistent result for same input

**Async Methods:**
- `HashPasswordWithPBKDF2Async`
- `ComputeHMACAsync`
- `HashPasswordWithArgon2Async`

#### Running Tests:

```bash
# Run all tests
dotnet test

# Run specific test category
dotnet test --filter "Category=PBKDF2"

# Verbose mode
dotnet test --verbosity detailed
```

---

### 2. Secure String Handling (Span<T>)

New methods for more secure password handling in memory:

#### New Interface Methods:

```csharp
// PBKDF2 with Span<char>
string HashPasswordWithPBKDF2Span(ReadOnlySpan<char> password, byte[] salt, 
    HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32);

// Verification with Span<char>
bool VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char> password, string storedHashString);

// Clear sensitive data
void ClearSensitiveData(byte[] data);
void ClearSensitiveData(Span<char> data);
```

#### Usage Example:

```csharp
ISecurityHelper helper = new SecurityHelper();

// Password kept as Span<char> (more secure than String)
ReadOnlySpan<char> password = "MySecurePassword".AsSpan();
byte[] salt = Convert.FromBase64String(helper.GenerateSalt());

// Create hash
string hash = helper.HashPasswordWithPBKDF2Span(password, salt, HashAlgorithmName.SHA256);

// Verify
bool isValid = helper.VerifyPasswordWithPBKDF2Span(password, hash);

// Clear sensitive data from memory
char[] tempPassword = password.ToArray();
helper.ClearSensitiveData(new Span<char>(tempPassword));
// Now all characters in tempPassword are '\0'
```

#### Benefits:

✅ **Span<T>**: Works on stack without heap allocation
✅ **ReadOnlySpan**: Stack-safe and performant
✅ **Automatic Zeroing**: `ClearSensitiveData` automatically clears sensitive data
✅ **No String Interning**: Strings can be retained by GC, Spans are under control

---

### 3. AES-GCM Conditional Compilation

AES-GCM encryption (.NET 6.0+) with conditional compilation:

```csharp
#if NET6_0_OR_GREATER
    // Full AES-GCM support
    string encrypted = helper.EncryptStringGCM(plainText, key);
#else
    // .NET Framework 4.8.1 - Throws NotSupportedException
    throw new NotSupportedException("AES-GCM is only available on .NET 6.0+");
#endif
```

---

## 📋 Project Structure

```
SecurityHelperLibrary/
├── SecurityHelperLibrary/
│   ├── SecurityHelperLibrary.cs (Main library)
│   ├── SecurityHelperLibrary.csproj
│   └── ...
├── SecurityHelperLibrary.Tests/
│   ├── SecurityHelperTests.cs (50+ unit tests)
│   ├── SecurityHelperLibrary.Tests.csproj
│   └── ...
└── SecurityHelperLibrary.sln
```

---

## 🧪 Test Statistics

| Category | Test Count |
|----------|-----------|
| ComputeHash | 3 |
| GenerateSalt | 3 |
| PBKDF2 | 5 |
| VerifyHash | 3 |
| VerifyPasswordWithPBKDF2 | 5 |
| HMAC | 3 |
| SymmetricKey | 3 |
| AES-GCM | 7 |
| Argon2 | 3 |
| Async Methods | 3 |
| Secure String Handling | 8 |
| **TOTAL** | **50+** |

---

## 🔒 Security Best Practices

1. **Use Span<char>**: Use Span<T> instead of String to keep data off GC heap
2. **Data Clearing**: Use `ClearSensitiveData` to clear sensitive data from memory
3. **Fixed-Time Comparison**: `FixedTimeEquals` is used to prevent timing attacks
4. **Random Nonce**: AES-GCM generates new nonce for each encryption
5. **Authenticated Encryption**: GCM mode ensures data integrity

---

## 📦 Dependencies

- **xunit** 2.6.6+ - Test framework
- **Microsoft.NET.Test.Sdk** 17.8.2+ - Test SDK
- **Isopoh.Cryptography.Argon2** 1.3.0+ - Argon2 hashing

---

## ⚙️ Build and Test

```bash
# Debug build
dotnet build

# Release build
dotnet build -c Release

# Run tests
dotnet test

# Code coverage (with CodeCov or similar tool)
dotnet test /p:CollectCoverage=true
```

---

## 📝 Test Examples

### PBKDF2 Verification Test
```csharp
[Fact]
public void VerifyPasswordWithPBKDF2_WithCorrectPassword_ReturnsTrue()
{
    // Arrange
    string password = "MySecurePassword";
    string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _);

    // Act
    bool result = _securityHelper.VerifyPasswordWithPBKDF2(password, storedHash);

    // Assert
    Assert.True(result);
}
```

### AES-GCM Round-Trip Test
```csharp
[Fact]
public void EncryptDecryptStringGCM_RoundTrip_PreservesData()
{
    string plainText = "Sensitive Data";
    byte[] key = _securityHelper.GenerateSymmetricKey();

    string encrypted = _securityHelper.EncryptStringGCM(plainText, key);
    string decrypted = _securityHelper.DecryptStringGCM(encrypted, key);

    Assert.Equal(plainText, decrypted);
}
```

### Secure String Handling Test
```csharp
[Fact]
public void HashPasswordWithPBKDF2Span_WithValidSpan_ReturnsValidHash()
{
    ReadOnlySpan<char> password = "MySecurePassword".AsSpan();
    byte[] salt = Convert.FromBase64String(_securityHelper.GenerateSalt());

    string hash = _securityHelper.HashPasswordWithPBKDF2Span(password, salt, 
        HashAlgorithmName.SHA256);

    Assert.NotNull(hash);
}
```

---

## 🚀 Advanced Features

- ✅ Multi-targeting (.NET Framework 4.8.1 & .NET 8.0)
- ✅ Conditional compilation (AES-GCM support)
- ✅ Async/await support
- ✅ Dependency Injection (ISecurityHelper interface)
- ✅ Comprehensive XML documentation
- ✅ Fixed-time comparison (timing attack prevention)

---

**Last Updated**: February 1, 2026
