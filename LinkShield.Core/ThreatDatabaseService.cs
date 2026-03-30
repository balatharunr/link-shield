using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

/// <summary>
/// Manages the local SQLite threat database lifecycle.
/// Provides fast domain lookups and bulk upsert for the sync worker.
/// </summary>
public class ThreatDatabaseService
{
    private readonly ILogger<ThreatDatabaseService> _logger;
    private readonly string _dbPath;

    public ThreatDatabaseService(ILogger<ThreatDatabaseService> logger, string? dbPath = null)
    {
        _logger = logger;
        _dbPath = dbPath ?? ThreatDbContext.GetDefaultDbPath();
    }

    /// <summary>
    /// Ensures the database and all tables/indexes exist.
    /// Called once on application startup.
    /// </summary>
    public async Task EnsureDatabaseAsync()
    {
        try
        {
            await using var context = CreateContext();
            await context.Database.EnsureCreatedAsync();

            // WAL is now set in the connection string (ThreatDbContext.OnConfiguring).
            // We still issue the PRAGMA once as a belt-and-suspenders measure since
            // the connection-string keyword depends on the SQLite provider version.
            await context.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
            _logger.LogInformation("Threat database initialized at {Path} (WAL mode)", _dbPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize threat database.");
            throw;
        }
    }

    /// <summary>
    /// Ultra-fast domain existence check against the indexed Domain column.
    /// Target: under 20ms.
    /// </summary>
    public async Task<bool> DomainExistsAsync(string domain)
    {
        await using var context = CreateContext();
        return await context.MaliciousDomains
            .AsNoTracking()
            .AnyAsync(d => d.Domain == domain);
    }

    /// <summary>
    /// Bulk upserts a set of domains into the database.
    /// Uses batched inserts with conflict-ignore to avoid duplicates.
    /// </summary>
    public async Task<int> BulkUpsertAsync(IEnumerable<string> domains)
    {
        await using var context = CreateContext();
        var existingDomainsList = await context.MaliciousDomains
            .AsNoTracking()
            .Select(d => d.Domain)
            .ToListAsync();
        var existingDomains = existingDomainsList.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var newDomains = domains
            .Where(d => !string.IsNullOrWhiteSpace(d) && !existingDomains.Contains(d))
            .Distinct()
            .Select(d => new MaliciousDomain
            {
                Domain = d,
                AddedAtUtc = DateTime.UtcNow
            })
            .ToList();

        if (newDomains.Count == 0)
        {
            _logger.LogInformation("No new domains to insert.");
            return 0;
        }

        // Batch insert in chunks to keep transactions short
        const int batchSize = 500;
        int totalInserted = 0;

        foreach (var batch in newDomains.Chunk(batchSize))
        {
            await using var batchContext = CreateContext();
            batchContext.MaliciousDomains.AddRange(batch);
            totalInserted += await batchContext.SaveChangesAsync();
        }

        _logger.LogInformation("Inserted {Count} new domains into threat database.", totalInserted);
        return totalInserted;
    }

    /// <summary>
    /// Returns the total number of domains in the database (useful for diagnostics).
    /// </summary>
    public async Task<int> GetDomainCountAsync()
    {
        await using var context = CreateContext();
        return await context.MaliciousDomains.CountAsync();
    }

    private ThreatDbContext CreateContext()
    {
        return new ThreatDbContext(_dbPath);
    }
}
