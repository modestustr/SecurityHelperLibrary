using Microsoft.AspNetCore.Mvc;
using SecurityHelperLibrary;
using SecurityHelperLibrary.Sample.Data;
using SecurityHelperLibrary.Sample.Models;
using SecurityHelperLibrary.Sample.Services;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecurityHelperLibrary.Sample.Controllers;

/// <summary>
/// API Controller for user authentication operations.
/// 
/// ARCHITECTURE:
/// - Endpoint: /api/auth
/// - Pattern: REST API with JSON request/response bodies
/// - Returns: HTTP status codes + JSON responses
/// 
/// SECURITY NOTES:
/// - All endpoints should be served over HTTPS in production
/// - Passwords are NEVER returned in responses
/// - Implement rate limiting on /register and /login to prevent brute-force attacks
/// - Consider adding JWT token generation on successful login
/// - Add CORS policy based on your frontend URL
/// 
/// ENDPOINTS PROVIDED:
/// 1. POST /api/auth/register - Create new user account
/// 2. POST /api/auth/login - Authenticate existing user
/// 3. GET /api/auth/check-username - Check if username is available
/// 4. GET /api/auth/check-email - Check if email is available
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    /// <summary>
    /// Service layer for user operations (dependency injected by ASP.NET Core).
    /// </summary>
    private readonly IUserService _userService;

    /// <summary>
    /// Database context for direct data access when needed.
    /// </summary>
    private readonly ApplicationDbContext _dbContext;

    /// <summary>
    /// Logger for recording events and errors (optional, for debugging).
    /// </summary>
    private readonly ILogger<AuthController> _logger;
    private static readonly RateLimiter RegisterRateLimiter = new(maxAttempts: 3, windowDurationSeconds: 60);
    private static readonly RateLimiter LoginRateLimiter = new(maxAttempts: 5, windowDurationSeconds: 60);

    /// <summary>
    /// Constructor - dependencies are injected automatically by ASP.NET Core DI container.
    /// </summary>
    public AuthController(IUserService userService, ApplicationDbContext dbContext, ILogger<AuthController> logger)
    {
        _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// ENDPOINT: POST /api/auth/register
    /// 
    /// PURPOSE: Register a new user account.
    /// 
    /// REQUEST BODY:
    /// {
    ///   "username": "john_doe",
    ///   "email": "john@example.com",
    ///   "password": "SecureP@ss123!",
    ///   "fullName": "John Doe"
    /// }
    /// 
    /// RESPONSE (Success - 201 Created):
    /// {
    ///   "success": true,
    ///   "message": "User registered successfully.",
    ///   "user": {
    ///     "id": 1,
    ///     "username": "john_doe",
    ///     "email": "john@example.com",
    ///     "fullName": "John Doe",
    ///     "isActive": true,
    ///     "createdAt": "2024-02-01T10:30:00Z"
    ///   }
    /// }
    /// 
    /// RESPONSE (Validation Error - 400 Bad Request):
    /// {
    ///   "success": false,
    ///   "message": "Username must be between 3 and 50 characters.",
    ///   "user": null
    /// }
    /// 
    /// HTTP STATUS CODES:
    /// - 201 Created: User successfully registered
    /// - 400 Bad Request: Validation error (invalid input)
    /// - 409 Conflict: Username or email already exists
    /// - 500 Internal Server Error: Unexpected server error
    /// 
    /// SECURITY CONSIDERATIONS:
    /// - Password is hashed with Argon2 before storage
    /// - Never returned in response
    /// - Request MUST be over HTTPS
    /// - Consider rate limiting (max 5 registrations per minute per IP)
    /// 
    /// CURL EXAMPLE:
    /// curl -X POST https://localhost:5001/api/auth/register \
    ///   -H "Content-Type: application/json" \
    ///   -d '{
    ///     "username": "john_doe",
    ///     "email": "john@example.com",
    ///     "password": "SecureP@ss123!",
    ///     "fullName": "John Doe"
    ///   }'
    /// </summary>
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        // INPUT VALIDATION: Check for null request
        if (request == null)
        {
            return BadRequest(new AuthResponse
            {
                Success = false,
                Message = "Request body is required."
            });
        }

        string registerIdentifier = request.Username.Trim().ToLowerInvariant();
        if (!RegisterRateLimiter.IsAllowed(registerIdentifier))
        {
            return TooManyAttempts("Too many registration attempts. Please wait a minute before trying again.");
        }

        // CALL SERVICE: Perform registration with all business logic
        var (success, message, user) = await _userService.RegisterUserAsync(
            request.Username,
            request.Email,
            request.Password,
            request.FullName
        );

        if (!success)
        {
            // Return 409 Conflict if user already exists, else 400 Bad Request
            int statusCode = message.Contains("already") ? StatusCodes.Status409Conflict : StatusCodes.Status400BadRequest;
            return StatusCode(statusCode, new AuthResponse
            {
                Success = false,
                Message = message
            });
        }

        // MAP TO DTO: Convert User entity to UserDto (excludes password hash)
        var userDto = MapToUserDto(user!);

        // RETURN: 201 Created with user data
        return CreatedAtAction(nameof(Register), new AuthResponse
        {
            Success = true,
            Message = message,
            User = userDto
        });
    }

    /// <summary>
    /// ENDPOINT: POST /api/auth/login
    /// 
    /// PURPOSE: Authenticate an existing user and return their data.
    /// 
    /// REQUEST BODY:
    /// {
    ///   "usernameOrEmail": "john@example.com",
    ///   "password": "SecureP@ss123!"
    /// }
    /// 
    /// RESPONSE (Success - 200 OK):
    /// {
    ///   "success": true,
    ///   "message": "Authentication successful.",
    ///   "user": {
    ///     "id": 1,
    ///     "username": "john_doe",
    ///     "email": "john@example.com",
    ///     "fullName": "John Doe",
    ///     "isActive": true,
    ///     "createdAt": "2024-02-01T10:30:00Z"
    ///   }
    /// }
    /// 
    /// RESPONSE (Invalid Credentials - 401 Unauthorized):
    /// {
    ///   "success": false,
    ///   "message": "Invalid username/email or password.",
    ///   "user": null
    /// }
    /// 
    /// HTTP STATUS CODES:
    /// - 200 OK: Authentication successful
    /// - 401 Unauthorized: Invalid credentials
    /// - 400 Bad Request: Missing required fields
    /// - 500 Internal Server Error: Unexpected error
    /// 
    /// SECURITY FEATURES:
    /// - Password verified using Argon2 (memory-hard, GPU-resistant)
    /// - Fixed-time comparison prevents timing attacks
    /// - Response time is consistent regardless of password length/mismatch position
    /// - Plaintext password is never stored or logged
    /// - Never reveals whether username or email exists (generic error message)
    /// 
    /// NEXT STEPS (In Production):
    /// After successful authentication, the client should:
    /// 1. Generate JWT token with user ID
    /// 2. Send token in Authorization header for protected endpoints
    /// 3. Store token in secure HTTP-only cookie
    /// 
    /// CURL EXAMPLE:
    /// curl -X POST https://localhost:5001/api/auth/login \
    ///   -H "Content-Type: application/json" \
    ///   -d '{
    ///     "usernameOrEmail": "john@example.com",
    ///     "password": "SecureP@ss123!"
    ///   }'
    /// </summary>
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        // INPUT VALIDATION
        if (request == null)
        {
            return BadRequest(new AuthResponse
            {
                Success = false,
                Message = "Request body is required."
            });
        }

        string loginIdentifier = request.UsernameOrEmail.Trim().ToLowerInvariant();
        if (!LoginRateLimiter.IsAllowed(loginIdentifier))
        {
            return TooManyAttempts("Too many login attempts. Try again in a minute.");
        }

        // CALL SERVICE: Authenticate user
        var (success, message, user) = await _userService.AuthenticateUserAsync(
            request.UsernameOrEmail,
            request.Password
        );

        if (!success)
        {
            // Return 401 Unauthorized on failed authentication
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = message
            });
        }

        // MAP TO DTO: Convert User entity to UserDto (excludes password hash)
        var userDto = MapToUserDto(user!);

        // RETURN: 200 OK with user data
        return Ok(new AuthResponse
        {
            Success = true,
            Message = message,
            User = userDto,
            DerivedKeys = BuildDerivedKeys(user, "session")
        });
    }

    /// <summary>
    /// ENDPOINT: GET /api/auth/check-username?username=john_doe
    /// 
    /// PURPOSE: Check if a username is available (before user fills out entire registration form).
    /// 
    /// RESPONSE (Username Available - 200 OK):
    /// {
    ///   "available": true,
    ///   "message": "Username is available."
    /// }
    /// 
    /// RESPONSE (Username Taken - 200 OK):
    /// {
    ///   "available": false,
    ///   "message": "Username is already taken."
    /// }
    /// 
    /// USE CASE:
    /// In frontend registration form, after user types username, call this endpoint
    /// to provide immediate feedback about availability.
    /// 
    /// CURL EXAMPLE:
    /// curl "https://localhost:5001/api/auth/check-username?username=john_doe"
    /// </summary>
    [HttpGet("check-username")]
    public async Task<ActionResult<object>> CheckUsername([FromQuery] string username)
    {
        // VALIDATION
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(new { available = false, message = "Username is required." });
        }

        // CHECK: Query service to see if username exists
        bool exists = await _userService.UsernameExistsAsync(username);

        return Ok(new
        {
            available = !exists,
            message = exists ? "Username is already taken." : "Username is available."
        });
    }

    /// <summary>
    /// ENDPOINT: GET /api/auth/check-email?email=john@example.com
    /// 
    /// PURPOSE: Check if an email is already registered.
    /// 
    /// RESPONSE (Email Available - 200 OK):
    /// {
    ///   "available": true,
    ///   "message": "Email is available."
    /// }
    /// 
    /// RESPONSE (Email Registered - 200 OK):
    /// {
    ///   "available": false,
    ///   "message": "Email is already registered."
    /// }
    /// 
    /// CURL EXAMPLE:
    /// curl "https://localhost:5001/api/auth/check-email?email=john@example.com"
    /// </summary>
    [HttpGet("check-email")]
    public async Task<ActionResult<object>> CheckEmail([FromQuery] string email)
    {
        // VALIDATION
        if (string.IsNullOrWhiteSpace(email))
        {
            return BadRequest(new { available = false, message = "Email is required." });
        }

        // CHECK: Query service to see if email exists
        bool exists = await _userService.EmailExistsAsync(email);

        return Ok(new
        {
            available = !exists,
            message = exists ? "Email is already registered." : "Email is available."
        });
    }

    /// <summary>
    /// HELPER METHOD: Maps User entity to UserDto.
    /// 
    /// PURPOSE: Prevents accidental exposure of sensitive fields (like PasswordHash).
    /// Always use DTOs when returning data in API responses.
    /// 
    /// PRINCIPLE: Never return more data than necessary.
    /// </summary>
    private UserDto MapToUserDto(User user)
    {
        return new UserDto
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            FullName = user.FullName,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        };
    }

    private static IEnumerable<DerivedKeyDto> BuildDerivedKeys(User user, string context)
    {
        byte[] seed = Encoding.UTF8.GetBytes(user.PasswordHash);
        byte[][] keys = KeyDerivation.DeriveMultipleKeys(
            HashAlgorithmName.SHA256,
            seed,
            keyCount: 2,
            keyLength: 32,
            context: context);

        return new[]
        {
            new DerivedKeyDto
            {
                Purpose = "SessionEncryption",
                Base64Key = Convert.ToBase64String(keys[0])
            },
            new DerivedKeyDto
            {
                Purpose = "SessionAuthentication",
                Base64Key = Convert.ToBase64String(keys[1])
            }
        };
    }

    private ActionResult<AuthResponse> TooManyAttempts(string message)
    {
        return StatusCode(StatusCodes.Status429TooManyRequests, new AuthResponse
        {
            Success = false,
            Message = message
        });
    }
}
