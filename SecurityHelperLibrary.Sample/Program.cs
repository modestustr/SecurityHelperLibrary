using Microsoft.EntityFrameworkCore;
using SecurityHelperLibrary;
using SecurityHelperLibrary.Sample.Data;
using SecurityHelperLibrary.Sample.Services;

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
/// 
var builder = WebApplicationBuilder.CreateBuilder(args);

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
builder.Services.AddScoped<ISecurityHelper, SecurityHelper>();

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

// Add authentication middleware (if you add JWT later)
// app.UseAuthentication();
// app.UseAuthorization();

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
