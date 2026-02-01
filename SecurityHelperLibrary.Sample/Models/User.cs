namespace SecurityHelperLibrary.Sample.Models;

/// <summary>
/// Represents a user in the system with secure password storage.
/// 
/// SECURITY NOTE:
/// - The PasswordHash field stores the hashed password using Argon2.
/// - The actual plaintext password is NEVER stored in the database.
/// - Always use the UserService to hash and verify passwords.
/// </summary>
public class User
{
    /// <summary>
    /// Unique identifier for the user.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Username - must be unique in the system.
    /// </summary>
    public required string Username { get; set; }

    /// <summary>
    /// User's email address - should be unique and validated.
    /// </summary>
    public required string Email { get; set; }

    /// <summary>
    /// The Argon2id hashed password.
    /// 
    /// Example format (hashed by Argon2):
    /// $argon2id$v=19$m=19456,t=2,p=1$[salt]$[hash]
    /// 
    /// Never compare this directly with user input!
    /// Always use UserService.VerifyPasswordAsync() for verification.
    /// </summary>
    public required string PasswordHash { get; set; }

    /// <summary>
    /// Full name of the user.
    /// </summary>
    public string? FullName { get; set; }

    /// <summary>
    /// Indicates whether the user account is active.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Timestamp of account creation.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Timestamp of last modification.
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
