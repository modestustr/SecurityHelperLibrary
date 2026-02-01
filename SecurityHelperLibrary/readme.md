# SecurityHelperLibrary v2.0.0

A comprehensive C# library for secure password hashing, symmetric encryption, and cryptographic operations.  
**Multi-targeted** for .NET Framework 4.8.1 and .NET 8.0, with modern secure-memory APIs and conditional AES-GCM support.

## ✨ Key Features (v2.0.0)

- **PBKDF2 Hashing**: SHA256, SHA384, SHA512 with configurable iterations
- **Argon2 Hashing**: Modern password hashing using Argon2id (recommended for new projects)
- **HMAC Generation**: Support for HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
- **AES-GCM Encryption** (.NET 6+): Authenticated encryption with Galois/Counter Mode
- **Span-based Secure APIs**: Low-alloc password handling with `ReadOnlySpan<char>` and `Span<char>`
- **Secure Memory Clearing**: Zero out sensitive data (passwords, keys) from memory
- **Fixed-Time Comparison**: Timing-attack resistant hash comparison
- **Cross-Framework Support**: net481 (with graceful fallbacks) and net8.0

## 🔄 Breaking Changes in v2.0.0

- `ISecurityHelper` interface now includes new methods (Span APIs, Argon2, etc.)
- AES-GCM methods throw `NotSupportedException` on .NET Framework 4.8.1
- Added required parameter `iterationCount` to PBKDF2 methods (was optional in v1)

## 📦 Installation

Add from local NuGet or via command line:

```bash
dotnet add package SecurityHelperLibrary
```

Or manually add to `.csproj`:
```xml
<ItemGroup>
  <PackageReference Include="SecurityHelperLibrary" Version="2.0.0" />
</ItemGroup>
```

## 📖 Usage Examples

### 1. Password Hashing with PBKDF2

**Legacy approach (v1 compatibility):**
```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper();

// Hash a password
byte[] salt = helper.GenerateSalt(16);
string passwordHash = helper.HashPasswordWithPBKDF2("MyPassword123", salt, 10000);

// Later, verify the password
bool isValid = helper.VerifyPasswordWithPBKDF2("MyPassword123", passwordHash);
```

**Modern Span-based approach (v2, recommended):**
```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper();

// Secure handling with Span<char>
ReadOnlySpan<char> password = "MyPassword123".AsSpan();
byte[] salt = helper.GenerateSalt(16);

// Hash password without full string allocation
string passwordHash = helper.HashPasswordWithPBKDF2Span(password, salt, 10000);

// Verify and automatically clear the span
bool isValid = helper.VerifyPasswordWithPBKDF2Span(password, passwordHash);

// Optional: explicitly clear sensitive data
Span<char> sensitiveBuffer = new char[100];
// ... use sensitiveBuffer ...
helper.ClearSensitiveData(sensitiveBuffer); // Securely zero out
```

### 2. Argon2 Hashing (Recommended for New Applications)

```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper();

// Hash password with Argon2id (modern, resistant to GPU attacks)
string argonHash = helper.HashPasswordWithArgon2("MyPassword123");

// Verify
bool isValid = helper.VerifyPasswordWithArgon2("MyPassword123", argonHash);
```

**Argon2 vs PBKDF2:**
- **Argon2**: Modern, memory-hard, GPU-resistant (use for new projects)
- **PBKDF2**: Simpler, standardized, suitable for strict security policies

### 3. AES-GCM Symmetric Encryption (.NET 6+)

```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper();

// Generate a symmetric key
byte[] key = helper.GenerateSymmetricKey(32); // 256-bit key

// Encrypt a string
string plaintext = "Sensitive data to encrypt";
string encrypted = helper.EncryptStringGCM(plaintext, key);
Console.WriteLine($"Encrypted: {encrypted}");

// Decrypt
string decrypted = helper.DecryptStringGCM(encrypted, key);
Console.WriteLine($"Decrypted: {decrypted}");
```

> **Note**: AES-GCM is only available on .NET 6+. Using on .NET Framework 4.8.1 throws `NotSupportedException`.

### 4. HMAC Generation and Verification

```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper();

string data = "Message to authenticate";
byte[] key = helper.GenerateSymmetricKey(32);

// Compute HMAC-SHA256
string hmac = helper.ComputeHMAC(data, key, HmacAlgorithm.SHA256);

// Use for integrity checks
bool isIntact = hmac == helper.ComputeHMAC(data, key, HmacAlgorithm.SHA256);
```

### 5. Hash Computation (SHA256, SHA384, SHA512)

```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper();

string data = "Data to hash";

// Compute SHA256 hash
string hash256 = helper.ComputeHash(data, HashAlgorithm.SHA256);
string hash384 = helper.ComputeHash(data, HashAlgorithm.SHA384);
string hash512 = helper.ComputeHash(data, HashAlgorithm.SHA512);

// Verify hash (fixed-time comparison to prevent timing attacks)
bool isValid = helper.VerifyHash(data, hash256, HashAlgorithm.SHA256);
```

### 6. Secure Memory Management

```csharp
using SecurityHelperLibrary;

var helper = new SecurityHelper();

// Working with byte arrays
byte[] sensitiveBytes = new byte[128];
// ... use sensitiveBytes ...
helper.ClearSensitiveData(sensitiveBytes); // Securely zeros the array

// Working with character spans
Span<char> password = new char[50];
// ... use password ...
helper.ClearSensitiveData(password); // Securely zeros the span
```

## 🔧 API Reference

### Core Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `GenerateSalt(int length)` | Generates cryptographically random salt | `byte[]` |
| `GenerateSymmetricKey(int length)` | Generates symmetric encryption key | `byte[]` |
| `ComputeHash(string data, HashAlgorithm algo)` | Computes hash (SHA256/384/512) | `string` |
| `ComputeHMAC(string data, byte[] key, HmacAlgorithm algo)` | Computes HMAC | `string` |

### PBKDF2 Methods

| Method | Description |
|--------|-------------|
| `HashPasswordWithPBKDF2(string password, byte[] salt, int iterations)` | Hash password with PBKDF2 |
| `HashPasswordWithPBKDF2Span(ReadOnlySpan<char> password, byte[] salt, int iterations)` | Span-based PBKDF2 hashing (low-alloc) |
| `VerifyPasswordWithPBKDF2(string password, string hash)` | Verify PBKDF2 hash |
| `VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char> password, string hash)` | Span-based PBKDF2 verification |

### Argon2 Methods

| Method | Description |
|--------|-------------|
| `HashPasswordWithArgon2(string password)` | Hash password with Argon2id (recommended) |
| `VerifyPasswordWithArgon2(string password, string hash)` | Verify Argon2 hash |

### AES-GCM Methods (.NET 6+)

| Method | Description | Platforms |
|--------|-------------|-----------|
| `EncryptStringGCM(string plaintext, byte[] key)` | Encrypt with AES-GCM | .NET 6+ |
| `DecryptStringGCM(string ciphertext, byte[] key)` | Decrypt AES-GCM ciphertext | .NET 6+ |

### Utility Methods

| Method | Description |
|--------|-------------|
| `ClearSensitiveData(byte[] data)` | Securely zero out byte array |
| `ClearSensitiveData(Span<char> data)` | Securely zero out character span |
| `FixedTimeEquals(string a, string b)` | Timing-attack resistant string comparison |

## 🧪 Testing

Run unit tests for both target frameworks:

```bash
dotnet build
dotnet test
```

Tests are located in `SecurityHelperLibrary.Tests` project and cover:
- ✅ All hashing algorithms (SHA256, SHA384, SHA512)
- ✅ PBKDF2 with multiple iterations
- ✅ Argon2 hashing and verification
- ✅ HMAC generation and verification
- ✅ AES-GCM encryption/decryption (.NET 8 only)
- ✅ Secure memory operations
- ✅ Span-based low-alloc APIs
- ✅ Async password hashing methods

## 🏗️ Building the Package

Build the project and create a NuGet package:

```bash
dotnet build -c Release
dotnet pack -c Release
```

Output: `bin/Release/SecurityHelperLibrary.2.0.0.nupkg`

## 📋 Requirements

- **.NET Framework 4.8.1** or **.NET 8.0**
- **NuGet Dependencies**: `Isopoh.Cryptography.Argon2`

## 📝 License

See [LICENSE.txt](../LICENSE.txt) for details.

## 🔐 Security Notes

- Use **Argon2** for new applications (GPU-resistant, memory-hard)
- Use **Span-based APIs** to minimize string allocations in memory
- Always call `ClearSensitiveData()` after using sensitive data
- Use **AES-GCM** for authenticated encryption (requires .NET 6+)
- Use **fixed-time comparison** (`FixedTimeEquals`) to prevent timing attacks
- Generate new salts for each password

## 📞 Support

For issues, questions, or contributions, please visit the [repository](https://github.com/modestustr/SecurityHelperLibrary).

---

**Version**: 2.0.0  
**Last Updated**: February 1, 2026
