using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

/// <summary>
/// Production URL analyzer with waterfall threat detection:
///   1. In-memory bootstrap blocklist (loaded from appsettings.json — zero DB latency)
///   2. Local SQLite threat database (indexed lookup, sub-20ms)
///   3. ML-based zero-day detection (ONNX model for unknown URLs)
///
/// The ML layer catches phishing URLs that aren't yet in any database,
/// providing protection against zero-day threats.
/// </summary>
public class SqliteUrlAnalyzer : IUrlAnalyzer
{
    private readonly ThreatDatabaseService _threatDb;
    private readonly ILogger<SqliteUrlAnalyzer> _logger;
    private readonly HashSet<string> _bootstrapBlocklist;
    private readonly LexicalMlScorer? _mlScorer;
    
    // ML threshold for blocking - URLs with score >= this are considered phishing
    private const float MlBlockThreshold = 0.85f;

    /// <param name="threatDb">The SQLite threat database service.</param>
    /// <param name="bootstrapDomains">Domains from appsettings.json "BootstrapBlocklist" array.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="mlScorer">Optional ML scorer for zero-day detection.</param>
    public SqliteUrlAnalyzer(
        ThreatDatabaseService threatDb,
        IEnumerable<string> bootstrapDomains,
        ILogger<SqliteUrlAnalyzer> logger,
        LexicalMlScorer? mlScorer = null)
    {
        _threatDb = threatDb;
        _logger = logger;
        _mlScorer = mlScorer;

        // Build a fast HashSet from config
        _bootstrapBlocklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in bootstrapDomains)
        {
            if (!string.IsNullOrWhiteSpace(domain))
                _bootstrapBlocklist.Add(domain.Trim());
        }

        _logger.LogInformation("Bootstrap blocklist loaded: {Count} domains", _bootstrapBlocklist.Count);
        _logger.LogInformation("ML zero-day detection: {Status}", 
            _mlScorer != null ? "ENABLED" : "DISABLED");
    }

    /// <summary>
    /// Waterfall threat check:
    ///   1. Bootstrap blocklist (in-memory HashSet — O(1), zero I/O)
    ///   2. SQLite threat DB (indexed B-tree lookup, ~5-15ms)
    ///   3. ML Model (ONNX inference, ~10-20ms) — catches zero-day threats
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

            // ═══════════════════════════════════════════════════════════════
            // Check 1: Bootstrap blocklist (instant, O(1))
            // ═══════════════════════════════════════════════════════════════
            if (_bootstrapBlocklist.Contains(domain))
            {
                _logger.LogWarning("[BOOTSTRAP] Domain '{Domain}' matched blocklist. BLOCKED.", domain);
                return true;
            }

            // ═══════════════════════════════════════════════════════════════
            // Check 2: SQLite database (sub-20ms)
            // ═══════════════════════════════════════════════════════════════
            var isInDatabase = await _threatDb.DomainExistsAsync(domain);
            if (isInDatabase)
            {
                _logger.LogWarning("[DATABASE] Domain '{Domain}' found in threat database. BLOCKED.", domain);
                return true;
            }

            // ═══════════════════════════════════════════════════════════════
            // Check 3: ML Zero-Day Detection (fallback for unknown URLs)
            // ═══════════════════════════════════════════════════════════════
            if (_mlScorer != null)
            {
                var mlScore = _mlScorer.GetThreatScore(url);
                
                if (mlScore >= MlBlockThreshold)
                {
                    _logger.LogWarning(
                        "[ML ZERO-DAY DETECTED] URL '{Url}' scored {Score:P1} (threshold: {Threshold:P0}). BLOCKED.",
                        url.Length > 60 ? url[..60] + "..." : url,
                        mlScore,
                        MlBlockThreshold);
                    return true;
                }
                
                _logger.LogDebug(
                    "[ML] URL '{Url}' scored {Score:P1} - below threshold, SAFE.",
                    url.Length > 40 ? url[..40] + "..." : url,
                    mlScore);
            }

            // All checks passed - URL is considered safe
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing URL '{Url}'. Failing open (treating as safe).", url);
            return false; // Fail-open: don't block users on errors
        }
    }
}
