using Microsoft.EntityFrameworkCore;
using SecurityHelperLibrary.Sample.Models;

namespace SecurityHelperLibrary.Sample.Data;

/// <summary>
/// Entity Framework Core DbContext for the application.
/// 
/// This class manages the database connection and provides DbSets
/// for entities like User, allowing LINQ queries and persistence.
/// 
/// ARCHITECTURE NOTE:
/// - Uses SQLite for simplicity (easy local development)
/// - Can be switched to SQL Server, PostgreSQL, etc. by changing the connection string and provider
/// - Database will be created automatically on first run (EnsureCreated or migrations)
/// </summary>
public class ApplicationDbContext : DbContext
{
    /// <summary>
    /// Initializes a new instance of the ApplicationDbContext.
    /// </summary>
    /// <param name="options">DbContext options (e.g., connection string, provider)</param>
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// DbSet for User entities.
    /// Allows querying, adding, updating, and deleting users from the database.
    /// </summary>
    public DbSet<User> Users { get; set; } = null!;

    /// <summary>
    /// Configures model constraints and relationships.
    /// 
    /// This is called during model creation to set up:
    /// - Unique constraints (Username, Email)
    /// - Column properties (max length, required fields)
    /// - Indexes for performance
    /// </summary>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure the User entity
        modelBuilder.Entity<User>(entity =>
        {
            // Set the table name (optional, defaults to "Users")
            entity.ToTable("Users");

            // Configure the primary key
            entity.HasKey(e => e.Id);

            // Configure properties
            entity.Property(e => e.Username)
                .IsRequired()
                .HasMaxLength(50);

            entity.Property(e => e.Email)
                .IsRequired()
                .HasMaxLength(100);

            entity.Property(e => e.PasswordHash)
                .IsRequired()
                .HasMaxLength(500); // Argon2 hashes can be quite long

            entity.Property(e => e.FullName)
                .HasMaxLength(100);

            // Create unique indexes on Username and Email
            // This ensures no two users have the same username or email
            entity.HasIndex(e => e.Username)
                .IsUnique()
                .HasDatabaseName("IX_Users_Username_Unique");

            entity.HasIndex(e => e.Email)
                .IsUnique()
                .HasDatabaseName("IX_Users_Email_Unique");

            // Create an index on IsActive for faster queries
            // (e.g., when filtering active users only)
            entity.HasIndex(e => e.IsActive)
                .HasDatabaseName("IX_Users_IsActive");
        });
    }
}
