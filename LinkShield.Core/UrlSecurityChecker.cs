using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

/// <summary>
/// Result of URL security analysis with detailed threat information.
/// </summary>
public class UrlSecurityResult
{
    public bool IsMalicious { get; set; }
    public string ThreatType { get; set; } = "None";
    public string ThreatDetails { get; set; } = "";
    public float? MlScore { get; set; }
    public bool DomainExists { get; set; } = true;
    public List<string> DetectedBrands { get; set; } = new();
    public bool IsGibberish { get; set; }
    public string RiskLevel { get; set; } = "Low"; // Low, Medium, High, Critical
}

/// <summary>
/// Enhanced URL security checker with multiple detection layers:
///   1. DNS Resolution Check - Detects non-existent domains
///   2. Brand Impersonation Detection - Catches fake brand combinations
///   3. Gibberish Domain Detection - Identifies random string domains
///   4. Risky TLD Detection - Flags high-risk top-level domains
/// </summary>
public partial class UrlSecurityChecker
{
    private readonly ILogger<UrlSecurityChecker> _logger;
    
    // Well-known brands that are commonly impersonated
    private static readonly HashSet<string> KnownBrands = new(StringComparer.OrdinalIgnoreCase)
    {
        // Tech giants
        "google", "microsoft", "apple", "amazon", "facebook", "meta", "instagram", "whatsapp",
        "twitter", "youtube", "netflix", "spotify", "linkedin", "github", "dropbox", "adobe",
        "zoom", "slack", "discord", "telegram", "tiktok", "snapchat", "pinterest", "reddit",
        
        // Financial/Banking
        "paypal", "venmo", "cashapp", "chase", "bankofamerica", "wellsfargo", "citibank",
        "capitalone", "americanexpress", "amex", "visa", "mastercard", "stripe", "square",
        "coinbase", "binance", "kraken", "robinhood",
        
        // E-commerce
        "ebay", "walmart", "target", "bestbuy", "costco", "aliexpress", "alibaba", "shopify",
        "etsy", "wayfair", "homedepot", "lowes", "ikea",
        
        // Email/Cloud
        "outlook", "hotmail", "yahoo", "gmail", "icloud", "onedrive", "office365", "office",
        
        // Shipping
        "fedex", "ups", "usps", "dhl", "amazon",
        
        // Gaming
        "steam", "epicgames", "playstation", "xbox", "nintendo", "roblox", "twitch"
    };
    
    // Suspicious keywords often used in phishing
    private static readonly HashSet<string> SuspiciousKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "login", "signin", "sign-in", "verify", "verification", "secure", "security",
        "account", "update", "confirm", "authenticate", "password", "credential",
        "suspend", "suspended", "locked", "unlock", "alert", "warning", "urgent",
        "expire", "expired", "billing", "payment", "invoice", "refund", "prize", "winner"
    };
    
    // High-risk TLDs commonly used in phishing
    private static readonly HashSet<string> RiskyTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tk", ".ml", ".ga", ".cf", ".gq",  // Free TLDs heavily abused
        ".xyz", ".top", ".work", ".click", ".link", ".info", ".biz",
        ".online", ".site", ".website", ".space", ".pw", ".cc", ".ws",
        ".buzz", ".surf", ".rest", ".fit", ".life", ".live", ".world"
    };
    
    // Legitimate domain suffixes (to avoid false positives)
    private static readonly HashSet<string> LegitDomainPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "github.com", "linkedin.com", "twitter.com", "x.com",
        "instagram.com", "whatsapp.com", "netflix.com", "paypal.com", "ebay.com"
    };
    
    // Regex for detecting IP addresses in URLs
    [GeneratedRegex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", RegexOptions.Compiled)]
    private static partial Regex IpAddressRegex();
    
    // Regex for detecting gibberish (consonant clusters)
    [GeneratedRegex(@"[bcdfghjklmnpqrstvwxz]{5,}", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ConsonantClusterRegex();

    public UrlSecurityChecker(ILogger<UrlSecurityChecker> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Performs comprehensive security analysis on a URL.
    /// </summary>
    public async Task<UrlSecurityResult> AnalyzeUrlAsync(string url)
    {
        var result = new UrlSecurityResult();
        
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                result.ThreatType = "InvalidUrl";
                result.ThreatDetails = "Could not parse URL";
                result.RiskLevel = "Medium";
                return result;
            }
            
            var domain = uri.Host.ToLowerInvariant();
            var domainWithoutWww = domain.StartsWith("www.") ? domain[4..] : domain;
            
            // Skip checks for known legitimate domains
            if (IsKnownLegitDomain(domainWithoutWww))
            {
                result.RiskLevel = "Low";
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 1: DNS Resolution - Does the domain exist?
            // ═══════════════════════════════════════════════════════════════
            var dnsResult = await CheckDnsResolutionAsync(domain);
            result.DomainExists = dnsResult.exists;
            
            if (!dnsResult.exists)
            {
                result.IsMalicious = true;
                result.ThreatType = "NonExistentDomain";
                result.ThreatDetails = $"Domain '{domain}' does not exist (DNS lookup failed)";
                result.RiskLevel = "High";
                _logger.LogWarning("[DNS] Domain '{Domain}' does not resolve. Likely fake/typosquatting.", domain);
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 2: IP Address in URL (common phishing tactic)
            // ═══════════════════════════════════════════════════════════════
            if (IpAddressRegex().IsMatch(domain))
            {
                result.IsMalicious = true;
                result.ThreatType = "IpAddressUrl";
                result.ThreatDetails = "URL uses IP address instead of domain name";
                result.RiskLevel = "High";
                _logger.LogWarning("[IP] URL uses raw IP address: {Domain}. SUSPICIOUS.", domain);
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 3: Brand Impersonation Detection
            // ═══════════════════════════════════════════════════════════════
            var brandResult = DetectBrandImpersonation(domainWithoutWww, url);
            result.DetectedBrands = brandResult.brands;
            
            if (brandResult.isSuspicious)
            {
                result.IsMalicious = true;
                result.ThreatType = "BrandImpersonation";
                result.ThreatDetails = brandResult.reason;
                result.RiskLevel = "Critical";
                _logger.LogWarning("[BRAND] Brand impersonation detected in '{Domain}': {Reason}", 
                    domain, brandResult.reason);
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 4: Gibberish Domain Detection
            // ═══════════════════════════════════════════════════════════════
            var gibberishResult = DetectGibberishDomain(domainWithoutWww);
            result.IsGibberish = gibberishResult.isGibberish;
            
            if (gibberishResult.isGibberish && HasSuspiciousContext(url))
            {
                result.IsMalicious = true;
                result.ThreatType = "GibberishDomain";
                result.ThreatDetails = $"Random/gibberish domain with suspicious context: {gibberishResult.reason}";
                result.RiskLevel = "High";
                _logger.LogWarning("[GIBBERISH] Suspicious gibberish domain: {Domain}", domain);
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 5: Risky TLD Detection
            // ═══════════════════════════════════════════════════════════════
            var tld = GetTld(domain);
            if (RiskyTlds.Contains(tld))
            {
                // Don't block, but flag as elevated risk
                result.RiskLevel = result.RiskLevel == "Low" ? "Medium" : result.RiskLevel;
                _logger.LogDebug("[TLD] Domain uses risky TLD: {Tld}", tld);
                
                // If combined with other suspicious signals, block
                if (result.IsGibberish || result.DetectedBrands.Count > 0)
                {
                    result.IsMalicious = true;
                    result.ThreatType = "RiskyTldCombination";
                    result.ThreatDetails = $"Risky TLD ({tld}) combined with suspicious domain pattern";
                    result.RiskLevel = "High";
                }
            }
            
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in URL security analysis for '{Url}'", url);
            return result; // Fail-open
        }
    }
    
    /// <summary>
    /// Quick DNS resolution check - returns whether domain exists.
    /// </summary>
    private async Task<(bool exists, string? ip)> CheckDnsResolutionAsync(string domain)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(domain);
            if (addresses.Length > 0)
            {
                return (true, addresses[0].ToString());
            }
            return (false, null);
        }
        catch (SocketException)
        {
            // DNS lookup failed - domain doesn't exist
            return (false, null);
        }
        catch (Exception ex)
        {
            _logger.LogDebug("DNS lookup error for {Domain}: {Error}", domain, ex.Message);
            // On error, assume domain exists (fail-open)
            return (true, null);
        }
    }
    
    /// <summary>
    /// Detects brand impersonation in domain names.
    /// </summary>
    private (bool isSuspicious, List<string> brands, string reason) DetectBrandImpersonation(string domain, string fullUrl)
    {
        var detectedBrands = new List<string>();
        var domainParts = domain.Split('.', '-', '_');
        
        // Find all brand names in the domain
        foreach (var brand in KnownBrands)
        {
            if (domain.Contains(brand, StringComparison.OrdinalIgnoreCase))
            {
                // Make sure it's not the actual brand's domain
                if (!IsActualBrandDomain(domain, brand))
                {
                    detectedBrands.Add(brand);
                }
            }
        }
        
        // Multiple brands = definitely suspicious
        if (detectedBrands.Count >= 2)
        {
            return (true, detectedBrands, 
                $"Multiple brand names detected: {string.Join(", ", detectedBrands)}");
        }
        
        // Single brand + suspicious keyword = suspicious
        if (detectedBrands.Count == 1)
        {
            var hasSuspiciousKeyword = SuspiciousKeywords.Any(k => 
                domain.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                fullUrl.Contains(k, StringComparison.OrdinalIgnoreCase));
            
            if (hasSuspiciousKeyword)
            {
                return (true, detectedBrands,
                    $"Brand '{detectedBrands[0]}' with suspicious keywords in URL");
            }
            
            // Brand name with unusual TLD
            var tld = GetTld(domain);
            if (RiskyTlds.Contains(tld))
            {
                return (true, detectedBrands,
                    $"Brand '{detectedBrands[0]}' on suspicious TLD ({tld})");
            }
        }
        
        return (false, detectedBrands, "");
    }
    
    /// <summary>
    /// Checks if this is the actual brand's domain (e.g., google.com, paypal.com).
    /// </summary>
    private bool IsActualBrandDomain(string domain, string brand)
    {
        // Check if domain IS the brand's official domain
        var officialPatterns = new[]
        {
            $"{brand}.com", $"{brand}.org", $"{brand}.net", $"{brand}.io",
            $"www.{brand}.com", $"www.{brand}.org"
        };
        
        return officialPatterns.Any(p => domain.Equals(p, StringComparison.OrdinalIgnoreCase)) ||
               domain.EndsWith($".{brand}.com", StringComparison.OrdinalIgnoreCase);
    }
    
    /// <summary>
    /// Detects gibberish/random string domains.
    /// </summary>
    private (bool isGibberish, string reason) DetectGibberishDomain(string domain)
    {
        // Get the main domain part (before TLD)
        var parts = domain.Split('.');
        if (parts.Length < 2) return (false, "");
        
        var mainPart = parts[^2]; // Second-to-last part (e.g., "fijnafkn" from "fijnafkn.com")
        
        // Check for consonant clusters (sign of random strings)
        if (ConsonantClusterRegex().IsMatch(mainPart))
        {
            return (true, "Contains unpronounceable consonant cluster");
        }
        
        // Check vowel ratio (real words typically have 30-50% vowels)
        var vowelCount = mainPart.Count(c => "aeiou".Contains(char.ToLower(c)));
        var vowelRatio = (float)vowelCount / mainPart.Length;
        
        if (mainPart.Length >= 6 && vowelRatio < 0.15f)
        {
            return (true, $"Very low vowel ratio ({vowelRatio:P0}) - likely random string");
        }
        
        // Check for excessive length without common patterns
        if (mainPart.Length > 15 && !mainPart.Contains('-'))
        {
            return (true, "Unusually long domain without hyphens");
        }
        
        return (false, "");
    }
    
    /// <summary>
    /// Checks if URL has suspicious context (path, query params).
    /// </summary>
    private bool HasSuspiciousContext(string url)
    {
        var lowerUrl = url.ToLowerInvariant();
        return SuspiciousKeywords.Any(k => lowerUrl.Contains(k));
    }
    
    /// <summary>
    /// Extracts TLD from domain.
    /// </summary>
    private string GetTld(string domain)
    {
        var lastDot = domain.LastIndexOf('.');
        return lastDot >= 0 ? domain[lastDot..] : "";
    }
    
    /// <summary>
    /// Checks if domain is a known legitimate site.
    /// </summary>
    private bool IsKnownLegitDomain(string domain)
    {
        return LegitDomainPatterns.Any(legit => 
            domain.Equals(legit, StringComparison.OrdinalIgnoreCase) ||
            domain.EndsWith("." + legit, StringComparison.OrdinalIgnoreCase));
    }
}
