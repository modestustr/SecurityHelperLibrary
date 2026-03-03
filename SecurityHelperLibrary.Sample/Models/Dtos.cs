using System.Collections.Generic;

namespace SecurityHelperLibrary.Sample.Models;

/// <summary>
/// DTO (Data Transfer Object) for user registration requests.
/// 
/// This class is used in API requests to avoid exposing the full User entity
/// and to validate input data.
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// Username chosen by the user.
    /// Should be alphanumeric and 3-20 characters long.
    /// </summary>
    public required string Username { get; set; }

    /// <summary>
    /// User's email address.
    /// Should be a valid email format.
    /// </summary>
    public required string Email { get; set; }

    /// <summary>
    /// Plaintext password provided by the user.
    /// 
    /// IMPORTANT: This is transmitted over HTTPS and is NEVER stored.
    /// It is immediately hashed using Argon2 and discarded.
    /// </summary>
    public required string Password { get; set; }

    /// <summary>
    /// User's full name (optional).
    /// </summary>
    public string? FullName { get; set; }
}

/// <summary>
/// DTO for user login requests.
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// Username or email of the user attempting to log in.
    /// </summary>
    public required string UsernameOrEmail { get; set; }

    /// <summary>
    /// Plaintext password provided during login.
    /// 
    /// Will be compared against the stored hash using fixed-time comparison
    /// to prevent timing attacks.
    /// </summary>
    public required string Password { get; set; }
}

/// <summary>
/// DTO for successful login/registration responses.
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// Indicates whether the authentication was successful.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Message providing details about the result.
    /// Examples: "User created successfully", "Invalid credentials", etc.
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// The authenticated user's data (without the password hash, obviously!).
    /// </summary>
    public UserDto? User { get; set; }

    /// <summary>
    /// Derived keys (HKDF/AES/HMAC) demonstrated by the sample.
    /// </summary>
    public IEnumerable<DerivedKeyDto>? DerivedKeys { get; set; }

    /// <summary>
    /// JWT access token for authenticated requests.
    /// </summary>
    public string? AccessToken { get; set; }

    /// <summary>
    /// Token type for Authorization header.
    /// </summary>
    public string? TokenType { get; set; }

    /// <summary>
    /// UTC expiration time of the access token.
    /// </summary>
    public DateTime? AccessTokenExpiresAtUtc { get; set; }

    /// <summary>
    /// Role embedded in the access token (for sample visibility).
    /// </summary>
    public string? Role { get; set; }
}

/// <summary>
/// Describes a derived key returned for demo purposes.
/// </summary>
public class DerivedKeyDto
{
    /// <summary>
    /// Purpose of the derived key (e.g., encryption, authentication).
    /// </summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>
    /// Base64-encoded derived key material.
    /// </summary>
    public string Base64Key { get; set; } = string.Empty;
}

/// <summary>
/// DTO for returning user information in API responses.
/// 
/// NOTE: Never includes PasswordHash or sensitive fields!
/// </summary>
public class UserDto
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FullName { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
}
