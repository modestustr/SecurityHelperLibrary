using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SecurityHelperLibrary;
using SecurityHelperLibrary.Sample.Data;
using SecurityHelperLibrary.Sample.Services;
using System.Text;

/// <summary>
/// Main Program.cs for ASP.NET Core Application.
/// 
/// This file configures:
/// - Dependency Injection (DI) container
/// - Entity Framework Core database
/// - Middleware pipeline
/// - Application startup
/// 
/// FLOW:
/// 1. Configure services (DI, database, logging, etc.)
/// 2. Build the web application
/// 3. Setup middleware (logging, routing, error handling)
/// 4. Initialize database (ensure created)
/// 5. Run the application
/// </summary>

var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// CONFIGURE SERVICES (Dependency Injection)
// ============================================================================

// Add logging to console (useful for debugging)
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Add controllers for API endpoints
builder.Services.AddControllers();

// Add API documentation (Swagger/OpenAPI)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

string jwtIssuer = builder.Configuration["SecurityAudit:Jwt:Issuer"] ?? "SecurityHelperLibrary.Sample";
string jwtAudience = builder.Configuration["SecurityAudit:Jwt:Audience"] ?? "SecurityHelperLibrary.Sample.Admin";
string jwtSigningKey = builder.Configuration["SecurityAudit:Jwt:SigningKey"] ?? "change-this-signing-key-at-least-32-characters";
byte[] jwtSigningKeyBytes = Encoding.UTF8.GetBytes(jwtSigningKey);
if (jwtSigningKeyBytes.Length < 32)
{
    throw new InvalidOperationException("SecurityAudit:Jwt:SigningKey must be at least 32 characters.");
}

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(jwtSigningKeyBytes),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

// CONFIGURE DATABASE: SQLite
// SQLite connection string points to "app.db" in the application directory
// This makes it easy to develop locally without setting up a database server
// In production, switch to SQL Server, PostgreSQL, Azure SQL, etc.
string connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Data Source=app.db"; // Fallback to local SQLite if not configured

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Use SQLite provider
    options.UseSqlite(connectionString);
    
    // Enable detailed logging for queries (development only!)
    if (builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging();
    }
});

// REGISTER SERVICES: Add custom business logic services
// 
// These interfaces/implementations are resolved from the DI container when:
// - Controllers request IUserService in their constructor
// - Services request ISecurityHelper in their constructor
//
// IMPORTANT: ISecurityHelper is from SecurityHelperLibrary package
//            We implement it as SecurityHelper (the concrete class)
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
builder.Services.AddSingleton<ISecurityIncidentStore, InMemorySecurityIncidentStore>();
builder.Services.AddScoped<ISecurityHelper>(serviceProvider =>
{
    var incidentStore = serviceProvider.GetRequiredService<ISecurityIncidentStore>();
    var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
    var incidentLogger = loggerFactory.CreateLogger("SecurityIncidents");

    return new SecurityHelper(incidentCode =>
    {
        incidentStore.Add(incidentCode);
        incidentLogger.LogWarning("Security incident detected: {IncidentCode}", incidentCode);
    });
});

// Add CORS (Cross-Origin Resource Sharing) for frontend access
// Configure this based on your frontend URL in production
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// ============================================================================
// BUILD APPLICATION
// ============================================================================

var app = builder.Build();

// ============================================================================
// MIDDLEWARE PIPELINE
// ============================================================================

// Enable Swagger in development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SecurityHelperLibrary Sample API v1");
        c.RoutePrefix = string.Empty; // Serve Swagger UI at root (/)
    });
}

// Redirect HTTP to HTTPS (security best practice)
app.UseHttpsRedirection();

// Enable CORS
app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

// Map controller routes
app.MapControllers();

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

// Ensure database exists and is up-to-date with current schema
// This runs migrations or creates the database if it doesn't exist
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    
    try
    {
        Console.WriteLine("Ensuring database is created and up-to-date...");
        
        // Create database if it doesn't exist
        dbContext.Database.EnsureCreated();
        
        // Optional: Apply migrations if you're using code-first migrations
        // dbContext.Database.Migrate();
        
        Console.WriteLine("Database initialization successful!");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Database initialization failed: {ex.Message}");
        throw;
    }
}

// ============================================================================
// START APPLICATION
// ============================================================================

app.Run();
