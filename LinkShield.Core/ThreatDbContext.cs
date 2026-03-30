using System;
using System.IO;
using Microsoft.EntityFrameworkCore;

namespace LinkShield.Core;

/// <summary>
/// EF Core DbContext for the local LinkShield threat database.
///
/// Deviation from original: WAL journal mode is now set IN the connection string
/// so every DbContext instance inherits it, not just the one that runs the PRAGMA.
/// This prevents write-locks blocking real-time reads in the interceptor path.
/// </summary>
public class ThreatDbContext : DbContext
{
    public DbSet<MaliciousDomain> MaliciousDomains => Set<MaliciousDomain>();

    private readonly string _dbPath;

    public ThreatDbContext(string? dbPath = null)
    {
        _dbPath = dbPath ?? GetDefaultDbPath();
    }

    public ThreatDbContext(DbContextOptions<ThreatDbContext> options) : base(options)
    {
        _dbPath = GetDefaultDbPath();
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            // WAL mode in connection string ensures ALL contexts use it, preventing
            // the daily sync worker from locking reads in the interceptor fast-path.
            var connectionString = $"Data Source={_dbPath};Cache=Shared";
            optionsBuilder.UseSqlite(connectionString);
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<MaliciousDomain>(entity =>
        {
            entity.HasIndex(e => e.Domain).IsUnique();
            entity.Property(e => e.Domain).IsRequired().HasMaxLength(512);
        });
    }

    public static string GetDefaultDbPath()
    {
        var folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LinkShield");
        Directory.CreateDirectory(folder);
        return Path.Combine(folder, "threats.db");
    }
}
