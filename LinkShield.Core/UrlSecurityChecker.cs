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
    public string RiskLevel { get; set; } = "Low"; // Low, Medium, High, Critical
}

/// <summary>
/// Enhanced URL security checker with multiple detection layers:
///   1. DNS Resolution Check - Detects non-existent domains (BLOCKS if no IP)
///   2. Brand Impersonation Detection - Catches fake brand combinations
///   3. Risky TLD Detection - Flags high-risk top-level domains
/// 
/// Note: Gibberish detection removed to avoid false positives on legitimate
/// short URLs (forms.gle, bit.ly, etc.) that use random-looking strings.
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
        "fedex", "ups", "usps", "dhl",
        
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
    
    // Legitimate domains and URL shorteners (whitelist to avoid false positives)
    private static readonly HashSet<string> LegitDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        // Major tech companies
        "google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "github.com", "linkedin.com", "twitter.com", "x.com",
        "instagram.com", "whatsapp.com", "netflix.com", "paypal.com", "ebay.com",
        "zoom.us", "dropbox.com", "slack.com", "discord.com", "twitch.tv",
        
        // Google domains
        "forms.gle", "goo.gl", "g.co", "google.co", "googleapis.com", "googleusercontent.com",
        "googlevideo.com", "gstatic.com", "ggpht.com", "google.co.in", "google.co.uk",
        
        // URL shorteners (legitimate)
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
        "lnkd.in", "db.tt", "qr.ae", "cur.lv", "ity.im", "q.gs", "po.st",
        "bc.vc", "su.pr", "j.mp", "buzurl.com", "cutt.ly", "u.teleportr.me",
        "rebrand.ly", "bl.ink", "short.io", "t.ly", "v.gd", "rb.gy",
        
        // Microsoft domains
        "microsoft.com", "office.com", "live.com", "outlook.com", "onedrive.com",
        "sharepoint.com", "azure.com", "msn.com", "bing.com", "linkedin.com",
        "aka.ms", "1drv.ms", "msft.it",
        
        // Other major services
        "amazonaws.com", "cloudfront.net", "firebase.com", "firebaseapp.com",
        "cloudflare.com", "akamaihd.net", "cdn.jsdelivr.net", "unpkg.com",
        "vercel.app", "netlify.app", "herokuapp.com", "pages.dev"
    };
    
    // Regex for detecting IP addresses in URLs
    [GeneratedRegex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", RegexOptions.Compiled)]
    private static partial Regex IpAddressRegex();

    public UrlSecurityChecker(ILogger<UrlSecurityChecker> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Performs comprehensive security analysis on a URL.
    /// Only blocks if:
    ///   1. Domain doesn't exist (no DNS/IP) - catches fake domains
    ///   2. URL uses raw IP address instead of domain
    ///   3. Brand impersonation detected (fake brand + suspicious patterns)
    /// </summary>
    public async Task<UrlSecurityResult> AnalyzeUrlAsync(string url)
    {
        var result = new UrlSecurityResult();
        
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                // Can't parse URL - don't block, let browser handle it
                result.RiskLevel = "Low";
                return result;
            }
            
            var domain = uri.Host.ToLowerInvariant();
            var domainWithoutWww = domain.StartsWith("www.") ? domain[4..] : domain;
            
            // ═══════════════════════════════════════════════════════════════
            // Whitelist Check: Skip all checks for known legitimate domains
            // ═══════════════════════════════════════════════════════════════
            if (IsKnownLegitDomain(domainWithoutWww))
            {
                _logger.LogDebug("[WHITELIST] Domain '{Domain}' is whitelisted. SAFE.", domain);
                result.RiskLevel = "Low";
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 1: DNS Resolution - Does the domain exist?
            // This is the KEY check - if no IP exists, domain is fake
            // ═══════════════════════════════════════════════════════════════
            var dnsResult = await CheckDnsResolutionAsync(domain);
            result.DomainExists = dnsResult.exists;
            
            if (!dnsResult.exists)
            {
                result.IsMalicious = true;
                result.ThreatType = "NonExistentDomain";
                result.ThreatDetails = $"Domain '{domain}' does not exist (no IP address found)";
                result.RiskLevel = "High";
                _logger.LogWarning("[DNS] Domain '{Domain}' has no IP. BLOCKED.", domain);
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 2: IP Address in URL (common phishing tactic)
            // ═══════════════════════════════════════════════════════════════
            if (IpAddressRegex().IsMatch(domain))
            {
                result.IsMalicious = true;
                result.ThreatType = "IpAddressUrl";
                result.ThreatDetails = "URL uses raw IP address instead of domain name";
                result.RiskLevel = "High";
                _logger.LogWarning("[IP] URL uses raw IP address: {Domain}. BLOCKED.", domain);
                return result;
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 3: Brand Impersonation Detection
            // Only blocks if domain contains brand + suspicious patterns
            // ═══════════════════════════════════════════════════════════════
            var brandResult = DetectBrandImpersonation(domainWithoutWww, url);
            result.DetectedBrands = brandResult.brands;
            
            if (brandResult.isSuspicious)
            {
                result.IsMalicious = true;
                result.ThreatType = "BrandImpersonation";
                result.ThreatDetails = brandResult.reason;
                result.RiskLevel = "Critical";
                _logger.LogWarning("[BRAND] Brand impersonation in '{Domain}': {Reason}. BLOCKED.", 
                    domain, brandResult.reason);
                return result;
            }
            
            // Domain exists and no suspicious patterns - SAFE
            _logger.LogDebug("[SAFE] Domain '{Domain}' passed all checks.", domain);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in URL security analysis for '{Url}'. Failing open.", url);
            return result; // Fail-open - don't block on errors
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
    /// Extracts TLD from domain.
    /// </summary>
    private string GetTld(string domain)
    {
        var lastDot = domain.LastIndexOf('.');
        return lastDot >= 0 ? domain[lastDot..] : "";
    }
    
    /// <summary>
    /// Checks if domain is a known legitimate site (whitelist).
    /// </summary>
    private bool IsKnownLegitDomain(string domain)
    {
        // Direct match
        if (LegitDomains.Contains(domain))
            return true;
        
        // Check if it's a subdomain of a whitelisted domain
        foreach (var legit in LegitDomains)
        {
            if (domain.EndsWith("." + legit, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        
        return false;
    }
}
