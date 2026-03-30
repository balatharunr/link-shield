using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

/// <summary>
/// Production URL analyzer. Checks URLs against:
///   1. In-memory bootstrap blocklist (loaded from appsettings.json — zero DB latency)
///   2. Local SQLite threat database (indexed lookup, sub-20ms)
///
/// Deviation from original: The hardcoded blocklist is replaced by a config-driven
/// string[] injected via constructor. This allows operators to add emergency blocks
/// without recompiling.
/// </summary>
public class SqliteUrlAnalyzer : IUrlAnalyzer
{
    private readonly ThreatDatabaseService _threatDb;
    private readonly ILogger<SqliteUrlAnalyzer> _logger;
    private readonly HashSet<string> _bootstrapBlocklist;

    /// <param name="threatDb">The SQLite threat database service.</param>
    /// <param name="bootstrapDomains">Domains from appsettings.json "BootstrapBlocklist" array.</param>
    /// <param name="logger">Logger instance.</param>
    public SqliteUrlAnalyzer(
        ThreatDatabaseService threatDb,
        IEnumerable<string> bootstrapDomains,
        ILogger<SqliteUrlAnalyzer> logger)
    {
        _threatDb = threatDb;
        _logger = logger;

        // Build a fast HashSet from config
        _bootstrapBlocklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in bootstrapDomains)
        {
            if (!string.IsNullOrWhiteSpace(domain))
                _bootstrapBlocklist.Add(domain.Trim());
        }

        _logger.LogInformation("Bootstrap blocklist loaded: {Count} domains", _bootstrapBlocklist.Count);
    }

    /// <summary>
    /// Check order:
    ///   1. Bootstrap blocklist (in-memory HashSet — O(1), zero I/O)
    ///   2. SQLite threat DB (indexed B-tree lookup, ~5-15ms)
    ///
    /// Fail-open: returns false on any error so the user isn't locked out.
    /// </summary>
    public async Task<bool> IsMaliciousAsync(string url)
    {
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                _logger.LogWarning("Could not parse URL: {Url}. Treating as safe (fail-open).", url);
                return false;
            }

            var domain = uri.Host.ToLowerInvariant();
            _logger.LogDebug("Checking domain '{Domain}'...", domain);

            // Check 1: Bootstrap blocklist (instant)
            if (_bootstrapBlocklist.Contains(domain))
            {
                _logger.LogWarning("Domain '{Domain}' matched bootstrap blocklist. MALICIOUS.", domain);
                return true;
            }

            // Check 2: SQLite database
            var isMalicious = await _threatDb.DomainExistsAsync(domain);

            if (isMalicious)
            {
                _logger.LogWarning("Domain '{Domain}' found in threat database. MALICIOUS.", domain);
            }

            return isMalicious;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing URL '{Url}'. Failing open.", url);
            return false;
        }
    }
}
