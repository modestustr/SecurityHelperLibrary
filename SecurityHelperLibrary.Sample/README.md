# SecurityHelperLibrary Sample - ASP.NET Core Application

A comprehensive sample ASP.NET Core project demonstrating how to use **SecurityHelperLibrary** for secure user authentication and password management.

## 📋 Project Overview

This project implements a simple but production-ready user authentication system that showcases:
- ✅ **Argon2id Password Hashing**: Modern, GPU-resistant algorithm from SecurityHelperLibrary
- ✅ **Secure Password Verification**: Fixed-time comparison to prevent timing attacks
- ✅ **Entity Framework Core**: Database persistence with SQLite (easily switchable)
- ✅ **REST API**: Clean endpoints for registration, login, and validation
- ✅ **Comprehensive Documentation**: Every piece of code is thoroughly commented
- ✅ **Best Practices**: Follows OWASP guidelines for authentication
- ✅ **Rate Limiting**: Built-in `RateLimiter` throttles repeated register/login attempts (demonstrated below)
- ✅ **Derived Key Material (HKDF)**: Uses `KeyDerivation.DeriveMultipleKeys` to produce session encryption/authentication keys for downstream scenarios

## 🏗️ Architecture

```
SecurityHelperLibrary.Sample/
├── Controllers/
│   └── AuthController.cs          # API endpoints (register, login, check availability)
├── Data/
│   └── ApplicationDbContext.cs     # Entity Framework Core DbContext
├── Models/
│   ├── User.cs                     # User entity with security annotations
│   └── Dtos.cs                     # Request/Response DTOs
├── Services/
│   └── UserService.cs              # Business logic for authentication
├── Program.cs                      # Application startup and DI configuration
├── appsettings.json               # Configuration (database connection, logging)
└── SecurityHelperLibrary.Sample.csproj  # Project file with dependencies
```

## 🔐 Security Features

### 1. **Argon2id Password Hashing**
- **Algorithm**: Argon2id (winner of Password Hashing Competition 2015)
- **Why**: Memory-hard, resistant to GPU/ASIC attacks
- **Performance**: ~50-100ms per hash (intentionally slow for security)
- **Storage Format**: `$argon2id$v=19$m=19456,t=2,p=1$[salt]$[hash]`

```csharp
// Password hashing happens automatically
string passwordHash = securityHelper.HashPasswordWithArgon2("MyPassword123");
// Never stored plaintext - always hashed
```

### 2. **Fixed-Time Comparison**
- **Problem**: Regular comparison leaks timing information via response time
- **Example**: Attacker measures response time to guess password patterns
- **Solution**: Always compares full strings regardless of mismatch position
- **Implementation**: SecurityHelperLibrary's `FixedTimeEquals()` method

```csharp
// Inside VerifyPasswordAsync - timing-attack resistant
bool isValid = securityHelper.VerifyPasswordWithArgon2(plainPassword, storedHash);
```

### 3. **Unique Constraints**
- Username and email are unique in database
- Prevents account enumeration attacks
- Enforced at both database and application level

### 4. **Input Validation**
- Username: 3-50 characters
- Email: Basic format validation
- Password: Minimum 6 characters (you may want stronger requirements)
- All inputs sanitized before database operations

### 5. **Rate Limiting with RateLimiter**
- Each request to `/api/auth/register` and `/api/auth/login` runs through the `RateLimiter` helper from the library, but each limiter tracks both the normalized username/email and the client IP address.
- Register attempts are limited to 3 hits per minute per username plus a higher per-IP ceiling, while logins are throttled to 5 attempts per user and 10 per IP per minute.
- Because `RateLimiter` is thread-safe, you can instantiate shared limiters as shown in `AuthController` and guard multiple endpoints without wiring middleware.

### 6. **Derived Key Material (HKDF)**
- After a successful login the sample now derives two 32-byte keys from a freshly generated session seed (not from any stored hash) via `KeyDerivation.DeriveMultipleKeys` so you can demonstrate key separation for encryption vs. authentication.
- The `DerivedKeys` section in the JSON response shows the Base64-encoded results; treat them as illustrative placeholders for how you might bootstrap session tokens, AK/SK pairs, or key-wrapping secrets.
- Because the sample references the main library project directly, this derivation automatically uses the latest HKDF fallback/`.NET 8` path without extra wiring.

### 7. **Span-safe Password Handling**
- The service now hashes passwords with `HashPasswordWithPBKDF2` using `password.AsSpan()` and a freshly generated salt (stored in the formatted hash string) to minimize the window where plaintext characters live in memory.
- The same `ReadOnlySpan<char>` overload is used in `VerifyPasswordAsync` so that the verifier never materializes a second string copy.

## 🚀 Getting Started

### Prerequisites
- .NET 8.0 SDK
- Visual Studio 2022 / VS Code
- Git

### Installation & Running

1. **Clone or navigate to the project:**
```bash
cd SecurityHelperLibrary.Sample
```

2. **Restore dependencies:**
```bash
dotnet restore
```

3. **Run the application:**
```bash
dotnet run
```

The API will start at `https://localhost:5001` (HTTPS) or `http://localhost:5000` (HTTP).

4. **View API documentation:**
Open `https://localhost:5001` in your browser to access Swagger UI.

## 📡 API Endpoints

### 1. Register New User
**POST** `/api/auth/register`

**Request:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecureP@ss123!",
  "fullName": "John Doe"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "User registered successfully.",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "fullName": "John Doe",
    "isActive": true,
    "createdAt": "2024-02-01T10:30:00Z"
  }
}
```

**cURL Example:**
```bash
curl -X POST https://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecureP@ss123!",
    "fullName": "John Doe"
  }'
```

### 2. Login User
**POST** `/api/auth/login`

**Request:**
```json
{
  "usernameOrEmail": "john@example.com",
  "password": "SecureP@ss123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Authentication successful.",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "fullName": "John Doe",
    "isActive": true,
    "createdAt": "2024-02-01T10:30:00Z"
  }
}
```

**cURL Example:**
```bash
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "john@example.com",
    "password": "SecureP@ss123!"
  }'
```

### 3. Check Username Availability
**GET** `/api/auth/check-username?username=john_doe`

**Response:**
```json
{
  "available": true,
  "message": "Username is available."
}
```

### 4. Check Email Availability
**GET** `/api/auth/check-email?email=john@example.com`

**Response:**
```json
{
  "available": false,
  "message": "Email is already registered."
}
```

### 5. Admin Security Incident Feed
**GET** `/api/security-audit/incidents?take=100`

This endpoint returns internal security incident codes captured by `SecurityHelper` (for example malformed PBKDF2 payload attempts). It does not expose attacker input payloads.

Access is protected by JWT role authorization: only tokens with `role=Admin` are accepted.

Admin role assignment is configured via `SecurityAudit:AdminUsers` in `appsettings.json`.

**Example Response:**
```json
[
  {
    "timestampUtc": "2026-03-03T16:31:09.125Z",
    "code": "PBKDF2_SPAN_FORMAT_PARTS"
  },
  {
    "timestampUtc": "2026-03-03T16:31:12.488Z",
    "code": "AES_GCM_DECRYPT_PARSE|FormatException"
  }
]
```

**Step 1: Login and get token**
```bash
curl -X POST "https://localhost:5001/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "admin",
    "password": "your-password"
  }'
```

Read `accessToken` from the login response.

**Step 2: Call admin incidents endpoint with Bearer token**
```bash
curl -X GET "https://localhost:5001/api/security-audit/incidents?take=50" \
  -H "Authorization: Bearer <accessToken>"
```

## 📝 Code Highlights

### UserService - Password Hashing
```csharp
string salt = _securityHelper.GenerateSalt();
byte[] saltBytes = Convert.FromBase64String(salt);
string passwordHash = _securityHelper.HashPasswordWithPBKDF2(
  password.AsSpan(),
  saltBytes,
  HashAlgorithmName.SHA256,
  iterations: 100000,
  hashLength: 32);
Array.Clear(saltBytes, 0, saltBytes.Length);
string storedHash = $"{HashAlgorithmName.SHA256.Name}|100000|{salt}|{passwordHash}";

// Store user with hashed password
var newUser = new User
{
  Username = username,
  PasswordHash = storedHash
};
```

### UserService - Password Verification
```csharp
// From UserService.cs - Login
public async Task<(bool Success, string Message, User? User)> AuthenticateUserAsync(...)
{
    // Find user
    var user = await _dbContext.Users
        .FirstOrDefaultAsync(u => u.Email.ToLower() == email.ToLower());

    if (user == null)
        return (false, "Invalid credentials.", null);

    // Verify password using Argon2 with fixed-time comparison
    bool passwordValid = await VerifyPasswordAsync(password, user.PasswordHash);

    if (!passwordValid)
        return (false, "Invalid credentials.", null);

    return (true, "Authentication successful.", user);
}
```

### Program.cs - Dependency Injection
```csharp
// Register SecurityHelperLibrary in DI container
builder.Services.AddScoped<ISecurityHelper, SecurityHelper>();

// Register custom service
builder.Services.AddScoped<IUserService, UserService>();

// When UserService is requested, ASP.NET Core automatically injects:
// - ApplicationDbContext (for database access)
// - ISecurityHelper (for password operations)
```

## 🔁 Keeping the Sample in Sync

- The sample project references `SecurityHelperLibrary.csproj` directly, so rebuilding the solution already uses the latest library code. Keep the reference as-is and avoid copying DLLs manually.
- Whenever the library ships a new feature (like `RateLimiter` or `KeyDerivation`), update this README and the controller/service logic to highlight it, just like we did for 2.1.2.
- Consider adding a simple smoke test or integration script that runs `dotnet run` in the sample after major changes to ensure the walkthrough still works.

## ⚠️ Security Warning: Registration Enumeration

- The sample always returns `200 OK` with a generic message when an account already exists even though the underlying service differentiates username/email collisions. This prevents attackers from enumerating valid accounts via timing or error code differences.
- In a production system you should still notify the real user (e.g., send an email) whenever someone resubmits their username or email so they can take action.

## 🗄️ Database Schema

**Users Table:**
```sql
CREATE TABLE Users (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Username NVARCHAR(50) NOT NULL UNIQUE,
    Email NVARCHAR(100) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(500) NOT NULL,
    FullName NVARCHAR(100),
    IsActive BOOLEAN NOT NULL DEFAULT 1,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IX_Users_Username_Unique ON Users(Username);
CREATE INDEX IX_Users_Email_Unique ON Users(Email);
CREATE INDEX IX_Users_IsActive ON Users(IsActive);
```

## 📚 Learning Points

### What This Sample Teaches:

1. **Real-World Security**
   - Never store passwords in plaintext
   - Use strong, modern algorithms (Argon2)
   - Implement timing-attack protections

2. **ASP.NET Core Best Practices**
   - Dependency injection and service layer pattern
   - Entity Framework Core for data access
   - REST API design with DTOs

3. **Production-Ready Code**
   - Comprehensive error handling
   - Input validation at multiple levels
   - Asynchronous operations (no blocking)

4. **Documentation as Code**
   - Every method thoroughly commented
   - Security considerations highlighted
   - Usage examples with cURL

## 🔄 Next Steps for Enhancement

### To make this production-ready:

1. **Add JWT Authentication**
   ```csharp
   // Issue JWT token on successful login
   var token = GenerateJwtToken(user);
   return Ok(new { token, user });
   ```

2. **Add Rate Limiting**
   ```csharp
   // Prevent brute-force attacks on /login and /register
   [Throttle(MaxRequests = 5, TimeWindow = "1m")]
   [HttpPost("login")]
   ```

3. **Add Email Verification**
   ```csharp
   // Send verification link on registration
   // Only activate account after email confirmation
   ```

4. **Add Password Reset**
   ```csharp
   // Send reset link via email
   // Validate token and allow new password
   ```

5. **Add Two-Factor Authentication (2FA)**
   ```csharp
   // Generate TOTP token using SecurityHelperLibrary
   // Verify during login
   ```

6. **Switch to SQL Server/PostgreSQL**
   ```csharp
   // Update Program.cs DbContext configuration
   options.UseSqlServer(connectionString);
   ```

7. **Add Logging**
   ```csharp
   _logger.LogInformation($"User {username} logged in successfully");
   _logger.LogWarning($"Failed login attempt for {username}");
   ```

## 🧪 Testing

Run the project and use the provided Swagger UI or cURL examples to test endpoints.

**Manual Test Scenario:**
```bash
# 1. Register a new user
curl -X POST https://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"Test123!"}'

# 2. Check if username exists
curl https://localhost:5001/api/auth/check-username?username=testuser

# 3. Try logging in with wrong password (should fail)
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"usernameOrEmail":"test@example.com","password":"WrongPassword"}'

# 4. Login with correct password (should succeed)
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"usernameOrEmail":"test@example.com","password":"Test123!"}'
```

### Automated smoke test script

Run the helper script in the repository root when you want a repeatable set of HTTP requests with no manual curl commands.

```powershell
.\scripts\run-sample-tests.ps1
```

By default the script starts the sample on HTTP port 5000, registers a fresh test user, checks availability, logs in, and tears the process down. Pass `-PreferHttps` if you want to exercise `https://localhost:5001`, or override `-HttpPort`/`-HttpsPort` if those bindings conflict with other services.

## 📄 Files Overview

| File | Purpose |
|------|---------|
| `AuthController.cs` | API endpoints with extensive comments on security |
| `UserService.cs` | Business logic using SecurityHelperLibrary for hashing/verification |
| `ApplicationDbContext.cs` | Entity Framework Core configuration and schema |
| `User.cs` | User entity model with security documentation |
| `Dtos.cs` | Request/Response data transfer objects |
| `Program.cs` | Application startup and dependency injection setup |
| `appsettings.json` | Configuration (database, logging) |

## 🔐 Security Checklist

- ✅ Passwords hashed with Argon2id (never plaintext)
- ✅ Fixed-time comparison for password verification
- ✅ Unique constraints on username/email
- ✅ Input validation on all endpoints
- ✅ DTOs used to prevent data exposure
- ✅ Async operations (no thread blocking)
- ✅ Database initialization handled
- ✅ HTTPS recommended for production
- ✅ Generic registration responses to prevent user enumeration (sample logs the attempt internally)

## 📖 References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Argon2 Paper](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
- [ASP.NET Core Security](https://docs.microsoft.com/en-us/aspnet/core/security/)
- [Entity Framework Core](https://docs.microsoft.com/en-us/ef/core/)

## 📞 Support

For issues or questions about SecurityHelperLibrary, visit:
[https://github.com/modestustr/SecurityHelperLibrary](https://github.com/modestustr/SecurityHelperLibrary)

## 📝 License

This sample project is provided as-is for educational purposes.

---

**Version**: 1.0.0  
**Last Updated**: February 1, 2026  
**Created For**: SecurityHelperLibrary v2.0.0
