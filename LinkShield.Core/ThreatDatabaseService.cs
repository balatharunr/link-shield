using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

/// <summary>
/// Manages the local SQLite threat database lifecycle.
/// Provides fast domain lookups and bulk upsert for the sync worker.
/// 
/// Performance optimizations:
///   - In-memory cache for ultra-fast lookups (refreshed on sync)
///   - Case-insensitive domain matching
///   - WAL mode for concurrent read/write
/// </summary>
public class ThreatDatabaseService
{
    private readonly ILogger<ThreatDatabaseService> _logger;
    private readonly string _dbPath;
    
    // In-memory cache for ultra-fast lookups (HashSet is O(1))
    private HashSet<string> _domainCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ReaderWriterLockSlim _cacheLock = new();
    private bool _cacheInitialized = false;

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
            
            // Initialize in-memory cache from database
            await RefreshCacheAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize threat database.");
            throw;
        }
    }

    /// <summary>
    /// Ultra-fast domain existence check using in-memory cache.
    /// Falls back to database if cache not initialized.
    /// Target: under 1ms with cache, under 20ms without.
    /// </summary>
    public async Task<bool> DomainExistsAsync(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return false;
            
        // Normalize domain to lowercase for consistent matching
        var normalizedDomain = domain.ToLowerInvariant();
        
        // Try cache first (ultra-fast O(1) lookup)
        _cacheLock.EnterReadLock();
        try
        {
            if (_cacheInitialized)
            {
                return _domainCache.Contains(normalizedDomain);
            }
        }
        finally
        {
            _cacheLock.ExitReadLock();
        }
        
        // Cache not initialized, fall back to database
        await using var context = CreateContext();
        return await context.MaliciousDomains
            .AsNoTracking()
            .AnyAsync(d => EF.Functions.Collate(d.Domain, "NOCASE") == normalizedDomain);
    }
    
    /// <summary>
    /// Synchronous domain check for performance-critical paths.
    /// Uses only the in-memory cache (no database access).
    /// </summary>
    public bool DomainExistsInCache(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return false;
            
        var normalizedDomain = domain.ToLowerInvariant();
        
        _cacheLock.EnterReadLock();
        try
        {
            return _cacheInitialized && _domainCache.Contains(normalizedDomain);
        }
        finally
        {
            _cacheLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Refreshes the in-memory cache from the database.
    /// Called after database initialization and after bulk upserts.
    /// </summary>
    public async Task RefreshCacheAsync()
    {
        try
        {
            await using var context = CreateContext();
            var domains = await context.MaliciousDomains
                .AsNoTracking()
                .Select(d => d.Domain.ToLower())
                .ToListAsync();
            
            // Build cache with domains both with and without www prefix for fast lookups
            var newCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var domain in domains)
            {
                var normalized = domain.StartsWith("www.") ? domain[4..] : domain;
                newCache.Add(normalized);
                // Also add www. variant for completeness
                newCache.Add("www." + normalized);
            }
            
            _cacheLock.EnterWriteLock();
            try
            {
                _domainCache = newCache;
                _cacheInitialized = true;
            }
            finally
            {
                _cacheLock.ExitWriteLock();
            }
            
            _logger.LogInformation("Domain cache refreshed with {Count} entries (including www variants)", newCache.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh domain cache");
        }
    }

    /// <summary>
    /// Bulk upserts a set of domains into the database.
    /// Uses batched inserts with conflict-ignore to avoid duplicates.
    /// Automatically refreshes the cache after insertion.
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
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => {
                var normalized = d.Trim().ToLowerInvariant();
                // Remove www. prefix for consistent storage
                return normalized.StartsWith("www.") ? normalized[4..] : normalized;
            })
            .Where(d => !existingDomains.Contains(d))
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
        
        // Refresh cache after bulk insert
        await RefreshCacheAsync();
        
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
