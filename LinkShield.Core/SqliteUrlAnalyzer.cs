using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

/// <summary>
/// Result of URL analysis with detailed information about each check.
/// </summary>
public class UrlAnalysisResult
{
    public bool IsMalicious { get; set; }
    public bool IsDead { get; set; }
    public bool IsTrusted { get; set; }
    public string ThreatType { get; set; } = "None";
    public string ThreatDetails { get; set; } = "";
    public float? MlScore { get; set; }
    public string CheckStage { get; set; } = ""; // Which stage determined the result
}

/// <summary>
/// Production URL analyzer with the correct waterfall detection order:
/// 
///   1. DNS Resolution Check (FIRST!) - If domain doesn't exist, mark as dead link
///   2. Trusted Domains Check - If domain is known safe (google.com, amzn.in, forms.gle), ALLOW
///   3. Blocklist Check - Check against known malicious domains in DB
///   4. Brand Impersonation Check - Detect fake brand domains
///   5. ML Model (LAST) - Only for unknown domains that passed all checks
///
/// This order ensures:
///   - Dead links are caught immediately (no point checking security for non-existent domains)
///   - Legitimate services with random-looking URLs (forms.gle/xyz) are not blocked
///   - ML is only used as final fallback for truly unknown URLs
/// </summary>
public class SqliteUrlAnalyzer : IUrlAnalyzer
{
    private readonly ThreatDatabaseService _threatDb;
    private readonly ILogger<SqliteUrlAnalyzer> _logger;
    private readonly HashSet<string> _bootstrapBlocklist;
    private readonly LexicalMlScorer? _mlScorer;
    private readonly UrlSecurityChecker? _securityChecker;
    private readonly NetworkStateChecker _networkChecker;
    
    // ML threshold for blocking - URLs with score >= this are considered phishing
    private const float MlBlockThreshold = 0.85f;

    public SqliteUrlAnalyzer(
        ThreatDatabaseService threatDb,
        IEnumerable<string> bootstrapDomains,
        ILogger<SqliteUrlAnalyzer> logger,
        LexicalMlScorer? mlScorer = null,
        UrlSecurityChecker? securityChecker = null,
        NetworkStateChecker? networkChecker = null)
    {
        _threatDb = threatDb;
        _logger = logger;
        _mlScorer = mlScorer;
        _securityChecker = securityChecker;
        _networkChecker = networkChecker ?? new NetworkStateChecker(
            LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Warning))
                .CreateLogger<NetworkStateChecker>());

        // Build a fast HashSet from config
        _bootstrapBlocklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in bootstrapDomains)
        {
            if (!string.IsNullOrWhiteSpace(domain))
                _bootstrapBlocklist.Add(domain.Trim());
        }

        _logger.LogInformation("URL Analyzer initialized:");
        _logger.LogInformation("  - Bootstrap blocklist: {Count} domains", _bootstrapBlocklist.Count);
        _logger.LogInformation("  - Trusted domains: {Count} domains", TrustedDomainsService.GetAllTrustedDomains().Count);
        _logger.LogInformation("  - ML detection: {Status}", _mlScorer != null ? "ENABLED" : "DISABLED");
        _logger.LogInformation("  - Security checks: {Status}", _securityChecker != null ? "ENABLED" : "DISABLED");
    }

    /// <summary>
    /// Analyzes a URL with detailed result information.
    /// 
    /// NEW WORKFLOW ORDER:
    ///   1. DNS Check (domain must exist)
    ///   2. Trusted Domains (whitelist for Google, Amazon, etc.)
    ///   3. Blocklist Check (known malicious)
    ///   4. Security Checks (brand impersonation)
    ///   5. ML Model (unknown URLs)
    /// </summary>
    public async Task<UrlAnalysisResult> AnalyzeUrlDetailedAsync(string url)
    {
        var result = new UrlAnalysisResult();
        
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                _logger.LogWarning("Could not parse URL: {Url}. Treating as suspicious.", url);
                result.IsMalicious = true;
                result.ThreatType = "InvalidUrl";
                result.ThreatDetails = "URL could not be parsed";
                result.CheckStage = "Parse";
                return result;
            }

            var domain = uri.Host.ToLowerInvariant();
            _logger.LogDebug("═══ Analyzing URL: {Url} ═══", url.Length > 60 ? url[..60] + "..." : url);
            _logger.LogDebug("Domain: {Domain}", domain);

            // ═══════════════════════════════════════════════════════════════
            // CHECK 1: DNS Resolution - Does the domain even exist?
            // This MUST be first - no point checking security for dead domains
            // ═══════════════════════════════════════════════════════════════
            var dnsResult = await _networkChecker.CheckDomainAsync(domain);
            
            if (!dnsResult.IsAlive)
            {
                result.IsDead = true;
                result.ThreatType = "DeadLink";
                result.ThreatDetails = dnsResult.ErrorMessage ?? "Domain does not exist (NXDOMAIN)";
                result.CheckStage = "DNS";
                _logger.LogWarning("[CHECK 1 - DNS] Domain '{Domain}' does not exist: {Error}", 
                    domain, dnsResult.ErrorMessage);
                return result;
            }
            
            _logger.LogDebug("[CHECK 1 - DNS] ✓ Domain '{Domain}' is alive (IP: {Ip})", 
                domain, dnsResult.ResolvedAddresses?[0]);

            // ═══════════════════════════════════════════════════════════════
            // CHECK 2: Trusted Domains - Is this a known legitimate service?
            // Whitelist for Google Forms, Amazon short links, etc.
            // ═══════════════════════════════════════════════════════════════
            if (TrustedDomainsService.IsTrustedDomain(domain))
            {
                result.IsTrusted = true;
                result.CheckStage = "Trusted";
                var brand = TrustedDomainsService.GetTrustedBrandForDomain(domain);
                _logger.LogDebug("[CHECK 2 - TRUSTED] ✓ Domain '{Domain}' is whitelisted{Brand}. ALLOWED.", 
                    domain, brand != null ? $" ({brand})" : "");
                return result;
            }
            
            _logger.LogDebug("[CHECK 2 - TRUSTED] Domain '{Domain}' not in whitelist, continuing checks...", domain);

            // ═══════════════════════════════════════════════════════════════
            // CHECK 3: Blocklist - Is this a known malicious domain?
            // ═══════════════════════════════════════════════════════════════
            
            // Check bootstrap blocklist (in-memory, instant)
            if (_bootstrapBlocklist.Contains(domain))
            {
                result.IsMalicious = true;
                result.ThreatType = "Blocklist";
                result.ThreatDetails = "Domain in bootstrap blocklist";
                result.CheckStage = "Bootstrap";
                _logger.LogWarning("[CHECK 3 - BLOCKLIST] Domain '{Domain}' in bootstrap blocklist. BLOCKED.", domain);
                return result;
            }

            // Check SQLite database
            var isInDatabase = await _threatDb.DomainExistsAsync(domain);
            if (isInDatabase)
            {
                result.IsMalicious = true;
                result.ThreatType = "Blocklist";
                result.ThreatDetails = "Domain found in threat database";
                result.CheckStage = "Database";
                _logger.LogWarning("[CHECK 3 - BLOCKLIST] Domain '{Domain}' in threat database. BLOCKED.", domain);
                return result;
            }
            
            _logger.LogDebug("[CHECK 3 - BLOCKLIST] ✓ Domain '{Domain}' not in blocklists", domain);

            // ═══════════════════════════════════════════════════════════════
            // CHECK 4: Security Analysis (brand impersonation, suspicious patterns)
            // ═══════════════════════════════════════════════════════════════
            if (_securityChecker != null)
            {
                var securityResult = await _securityChecker.AnalyzeUrlAsync(url);
                
                if (securityResult.IsMalicious)
                {
                    result.IsMalicious = true;
                    result.ThreatType = securityResult.ThreatType;
                    result.ThreatDetails = securityResult.ThreatDetails;
                    result.CheckStage = "Security";
                    _logger.LogWarning("[CHECK 4 - SECURITY] {ThreatType}: {Details}. BLOCKED.",
                        securityResult.ThreatType, securityResult.ThreatDetails);
                    return result;
                }
                
                _logger.LogDebug("[CHECK 4 - SECURITY] ✓ No brand impersonation or suspicious patterns detected");
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 5: ML Model - Final check for unknown URLs
            // Only runs if all other checks passed
            // ═══════════════════════════════════════════════════════════════
            if (_mlScorer != null)
            {
                var mlScore = _mlScorer.GetThreatScore(url);
                result.MlScore = mlScore;
                
                if (mlScore >= MlBlockThreshold)
                {
                    result.IsMalicious = true;
                    result.ThreatType = "MlDetection";
                    result.ThreatDetails = $"ML model scored {mlScore:P1} (threshold: {MlBlockThreshold:P0})";
                    result.CheckStage = "ML";
                    _logger.LogWarning("[CHECK 5 - ML] URL scored {Score:P1} (>= {Threshold:P0}). BLOCKED.",
                        mlScore, MlBlockThreshold);
                    return result;
                }
                
                _logger.LogDebug("[CHECK 5 - ML] ✓ URL scored {Score:P1} (< {Threshold:P0}) - SAFE",
                    mlScore, MlBlockThreshold);
            }

            // All checks passed - URL is considered safe
            result.CheckStage = "Complete";
            _logger.LogDebug("═══ URL ANALYSIS COMPLETE: SAFE ═══");
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing URL '{Url}'. Failing closed (blocking).", url);
            result.IsMalicious = true;
            result.ThreatType = "Error";
            result.ThreatDetails = $"Analysis error: {ex.Message}";
            result.CheckStage = "Error";
            return result;
        }
    }

    /// <summary>
    /// Simple malicious check for backward compatibility.
    /// Returns true if URL is malicious (should be blocked).
    /// Returns false if URL is safe OR dead (dead links handled separately).
    /// </summary>
    public async Task<bool> IsMaliciousAsync(string url)
    {
        var result = await AnalyzeUrlDetailedAsync(url);
        return result.IsMalicious;
    }
    
    /// <summary>
    /// Check if URL points to a dead domain.
    /// </summary>
    public async Task<bool> IsDeadLinkAsync(string url)
    {
        var result = await AnalyzeUrlDetailedAsync(url);
        return result.IsDead;
    }
}
