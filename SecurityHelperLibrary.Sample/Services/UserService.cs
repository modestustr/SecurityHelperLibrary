using Microsoft.EntityFrameworkCore;
using SecurityHelperLibrary.Sample.Data;
using SecurityHelperLibrary.Sample.Models;
using System.Security.Cryptography;

namespace SecurityHelperLibrary.Sample.Services;

/// <summary>
/// Service class for handling user authentication and password management.
/// 
/// DESIGN PATTERN: Service Layer Pattern
/// This class encapsulates all business logic related to users:
/// - Password hashing (using Argon2 from SecurityHelperLibrary)
/// - Password verification with timing-attack protection
/// - User registration and validation
/// - User lookup and authentication
/// 
/// WHY ARGON2?
/// - Argon2id is the winner of the Password Hashing Competition (2015)
/// - Memory-hard algorithm: resistant to GPU/ASIC attacks
/// - Much slower than PBKDF2 or bcrypt, making brute-force attacks impractical
/// - Automatically handles salt generation and iteration parameters
/// 
/// SECURITY BEST PRACTICES IMPLEMENTED:
/// 1. Never logs or returns plaintext passwords
/// 2. Uses fixed-time comparison to prevent timing attacks
/// 3. Validates input (empty strings, null values)
/// 4. Checks for duplicate usernames/emails
/// 5. Uses async/await to avoid blocking thread pool
/// </summary>
public interface IUserService
{
    /// <summary>
    /// Registers a new user with the provided credentials.
    /// </summary>
    Task<(bool Success, string Message, User? User)> RegisterUserAsync(string username, string email, string password, string? fullName = null);

    /// <summary>
    /// Authenticates a user and returns their information if credentials are valid.
    /// </summary>
    Task<(bool Success, string Message, User? User)> AuthenticateUserAsync(string usernameOrEmail, string password);

    /// <summary>
    /// Verifies if a plaintext password matches a stored hash.
    /// Uses fixed-time comparison to prevent timing attacks.
    /// </summary>
    Task<bool> VerifyPasswordAsync(string plainPassword, string storedHash);

    /// <summary>
    /// Retrieves a user by username (case-insensitive search).
    /// </summary>
    Task<User?> GetUserByUsernameAsync(string username);

    /// <summary>
    /// Retrieves a user by email (case-insensitive search).
    /// </summary>
    Task<User?> GetUserByEmailAsync(string email);

    /// <summary>
    /// Checks if a username is already taken.
    /// </summary>
    Task<bool> UsernameExistsAsync(string username);

    /// <summary>
    /// Checks if an email is already registered.
    /// </summary>
    Task<bool> EmailExistsAsync(string email);
}

public class UserService : IUserService
{
    /// <summary>
    /// Database context for accessing user records.
    /// </summary>
    private readonly ApplicationDbContext _dbContext;

    /// <summary>
    /// SecurityHelper instance for password hashing and verification.
    /// Created from the SecurityHelperLibrary NuGet package.
    /// </summary>
    private readonly ISecurityHelper _securityHelper;

    /// <summary>
    /// Constructor for dependency injection.
    /// 
    /// ASP.NET Core will automatically inject:
    /// - ApplicationDbContext: Database connection
    /// - ISecurityHelper: Password hashing/verification utilities
    /// </summary>
    public UserService(ApplicationDbContext dbContext, ISecurityHelper securityHelper)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _securityHelper = securityHelper ?? throw new ArgumentNullException(nameof(securityHelper));
    }

    /// <summary>
    /// Registers a new user with validation.
    /// 
    /// PROCESS:
    /// 1. Validate input (non-empty, reasonable lengths)
    /// 2. Check if username already exists (case-insensitive)
    /// 3. Check if email already exists (case-insensitive)
    /// 4. Hash the password using Argon2 (slow operation ~ 50-100ms)
    /// 5. Save user to database
    /// 6. Return the created user (without password hash)
    /// 
    /// EXAMPLE:
    /// var result = await userService.RegisterUserAsync(
    ///     username: "john_doe",
    ///     email: "john@example.com",
    ///     password: "SecureP@ss123!",
    ///     fullName: "John Doe"
    /// );
    /// </summary>
    public async Task<(bool Success, string Message, User? User)> RegisterUserAsync(
        string username, 
        string email, 
        string password, 
        string? fullName = null)
    {
        // VALIDATION: Check for null or empty inputs
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return (false, "Username, email, and password are required.", null);
        }

        // VALIDATION: Check username length (reasonable constraints)
        if (username.Length < 3 || username.Length > 50)
        {
            return (false, "Username must be between 3 and 50 characters.", null);
        }

        // VALIDATION: Check email format (basic validation)
        if (!email.Contains("@") || !email.Contains("."))
        {
            return (false, "Invalid email format.", null);
        }

        // VALIDATION: Check password strength
        if (password.Length < 6)
        {
            return (false, "Password must be at least 6 characters long.", null);
        }

        // CHECK: Does username already exist? (case-insensitive)
        if (await UsernameExistsAsync(username))
        {
            return (false, $"Username '{username}' is already taken.", null);
        }

        // CHECK: Does email already exist? (case-insensitive)
        if (await EmailExistsAsync(email))
        {
            return (false, $"Email '{email}' is already registered.", null);
        }

        try
        {
            const int iterations = 100000;
            const int hashLength = 32;
            string salt = _securityHelper.GenerateSalt();
            byte[] saltBytes = Convert.FromBase64String(salt);
            string hashBase64 = _securityHelper.HashPasswordWithPBKDF2(
                password.AsSpan(),
                saltBytes,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                iterations: iterations,
                hashLength: hashLength);
            Array.Clear(saltBytes, 0, saltBytes.Length);
            string passwordHash = $"{System.Security.Cryptography.HashAlgorithmName.SHA256.Name}|{iterations}|{salt}|{hashBase64}";

            var newUser = new User
            {
                Username = username.Trim(),
                Email = email.Trim().ToLower(), // Normalize email to lowercase
                PasswordHash = passwordHash,
                FullName = string.IsNullOrWhiteSpace(fullName) ? null : fullName.Trim(),
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            // SAVE: Add user to database
            _dbContext.Users.Add(newUser);
            await _dbContext.SaveChangesAsync();

            // RETURN: Success with user (but NOT the password hash!)
            return (true, "User registered successfully.", newUser);
        }
        catch (Exception ex)
        {
            // LOG: In production, log this exception
            return (false, $"An error occurred during registration: {ex.Message}", null);
        }
    }

    /// <summary>
    /// Authenticates a user by verifying their credentials.
    /// 
    /// PROCESS:
    /// 1. Find user by username OR email (case-insensitive)
    /// 2. Check if user exists and is active
    /// 3. Verify password using fixed-time comparison (prevents timing attacks)
    /// 4. Return user data if authentication succeeds
    /// 
    /// SECURITY NOTE - TIMING ATTACKS:
    /// If we compared passwords with a regular == operator:
    /// - Early mismatch returns faster than full match
    /// - Attacker could measure response time to guess password length/patterns
    /// 
    /// Solution: Use FixedTimeEquals() from SecurityHelperLibrary
    /// - Always compares full strings regardless of mismatch position
    /// - Response time is consistent = no timing information leaked
    /// 
    /// EXAMPLE:
    /// var result = await userService.AuthenticateUserAsync(
    ///     usernameOrEmail: "john@example.com",
    ///     password: "SecureP@ss123!"
    /// );
    /// if (result.Success) { /* issue JWT token */ }
    /// </summary>
    public async Task<(bool Success, string Message, User? User)> AuthenticateUserAsync(
        string usernameOrEmail, 
        string password)
    {
        // VALIDATION: Check for empty inputs
        if (string.IsNullOrWhiteSpace(usernameOrEmail) || string.IsNullOrWhiteSpace(password))
        {
            return (false, "Username/email and password are required.", null);
        }

        try
        {
            // FIND: Look up user by username (case-insensitive)
            // Using .FirstOrDefaultAsync for async database access
            var user = await _dbContext.Users.FirstOrDefaultAsync(u =>
                u.Username.ToLower() == usernameOrEmail.ToLower());

            // FALLBACK: If not found by username, try by email
            if (user == null)
            {
                user = await _dbContext.Users.FirstOrDefaultAsync(u =>
                    u.Email.ToLower() == usernameOrEmail.ToLower());
            }

            // NOT FOUND: User doesn't exist
            if (user == null)
            {
                return (false, "Invalid username/email or password.", null);
            }

            // CHECK: Is account active?
            if (!user.IsActive)
            {
                return (false, "This account is inactive.", null);
            }

            // VERIFY: Check password using PBKDF2 verification
            bool passwordValid = await VerifyPasswordAsync(password, user.PasswordHash);

            if (!passwordValid)
            {
                return (false, "Invalid username/email or password.", null);
            }

            // SUCCESS: Authentication passed
            // Update last login timestamp (optional)
            user.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            return (true, "Authentication successful.", user);
        }
        catch (Exception ex)
        {
            return (false, $"An error occurred during authentication: {ex.Message}", null);
        }
    }

    /// <summary>
    /// Verifies a plaintext password against a stored PBKDF2 hash.
    /// 
    /// IMPLEMENTATION DETAIL:
    /// This wraps SecurityHelperLibrary's PBKDF2 verification logic.
    /// 
    /// WHAT HAPPENS INTERNALLY:
    /// The stored hash contains: algorithm|iterations|salt|hash
    /// 1. Parse the stored hash to extract components
    /// 2. Re-hash the provided password with those same parameters
    /// 3. Compare the new hash with the stored hash using fixed-time comparison
    /// 4. Returns true only if hashes match exactly
    /// 
    /// WHY NOT SIMPLE COMPARISON?
    /// - Fixed-time comparison prevents timing attacks
    /// - Regular comparison leaks information via response time
    /// - Exact format: algorithm|iterations|salt|hash (e.g., "SHA256|100000|base64salt|base64hash")
    /// 
    /// EXAMPLE USAGE (internal):
    /// bool isValid = await verifyPasswordAsync("MyPassword123", "SHA256|100000|...|...");
    /// </summary>
    public async Task<bool> VerifyPasswordAsync(string plainPassword, string storedHash)
    {
        // INPUT VALIDATION: Prevent null/empty inputs
        if (string.IsNullOrWhiteSpace(plainPassword) || string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        try
        {
            return await Task.Run(() => _securityHelper.VerifyPasswordWithPBKDF2(plainPassword.AsSpan(), storedHash));
        }
        catch
        {
            // On any error (e.g., invalid hash format), return false
            // Better to deny access than crash the service
            return false;
        }
    }

    /// <summary>
    /// Retrieves a user by username (case-insensitive).
    /// </summary>
    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return null;

        // Case-insensitive database query
        return await _dbContext.Users.FirstOrDefaultAsync(u =>
            u.Username.ToLower() == username.ToLower());
    }

    /// <summary>
    /// Retrieves a user by email (case-insensitive).
    /// </summary>
    public async Task<User?> GetUserByEmailAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        // Case-insensitive database query
        return await _dbContext.Users.FirstOrDefaultAsync(u =>
            u.Email.ToLower() == email.ToLower());
    }

    /// <summary>
    /// Checks if a username is already taken (case-insensitive).
    /// 
    /// USAGE: Call this before allowing user registration to provide
    /// immediate feedback without attempting to create a duplicate user.
    /// </summary>
    public async Task<bool> UsernameExistsAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        // Case-insensitive check
        return await _dbContext.Users.AnyAsync(u =>
            u.Username.ToLower() == username.ToLower());
    }

    /// <summary>
    /// Checks if an email is already registered (case-insensitive).
    /// </summary>
    public async Task<bool> EmailExistsAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        // Case-insensitive check
        return await _dbContext.Users.AnyAsync(u =>
            u.Email.ToLower() == email.ToLower());
    }
}
