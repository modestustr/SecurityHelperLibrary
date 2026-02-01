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
