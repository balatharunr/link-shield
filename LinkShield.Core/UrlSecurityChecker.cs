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
    public List<string> DetectedBrands { get; set; } = new();
    public string RiskLevel { get; set; } = "Low"; // Low, Medium, High, Critical
}

/// <summary>
/// URL security checker for detecting phishing/malicious URLs.
/// 
/// This class handles SECURITY checks only (brand impersonation, risky TLDs).
/// Dead link detection (NXDOMAIN) is handled separately by NetworkStateChecker
/// in the interceptor flow AFTER security checks pass.
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
    
    // Regex for detecting IP addresses in URLs
    [GeneratedRegex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", RegexOptions.Compiled)]
    private static partial Regex IpAddressRegex();

    public UrlSecurityChecker(ILogger<UrlSecurityChecker> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Performs security analysis on a URL to detect phishing/malicious content.
    /// 
    /// Checks:
    ///   1. Skip if domain is in trusted whitelist (handled by TrustedDomainsService)
    ///   2. Raw IP address in URL (common phishing tactic)
    ///   3. Brand impersonation (fake brand + suspicious patterns)
    /// 
    /// NOTE: DNS check is done BEFORE this in SqliteUrlAnalyzer.
    /// </summary>
    public Task<UrlSecurityResult> AnalyzeUrlAsync(string url)
    {
        var result = new UrlSecurityResult();
        
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                // Can't parse URL - don't block, let browser handle it
                result.RiskLevel = "Low";
                return Task.FromResult(result);
            }
            
            var domain = uri.Host.ToLowerInvariant();
            var domainWithoutWww = domain.StartsWith("www.") ? domain[4..] : domain;
            
            // ═══════════════════════════════════════════════════════════════
            // Skip Check: Trusted domains are already validated by TrustedDomainsService
            // This is a safety net in case UrlSecurityChecker is called directly
            // ═══════════════════════════════════════════════════════════════
            if (TrustedDomainsService.IsTrustedDomain(domain))
            {
                _logger.LogDebug("[TRUSTED] Skipping security checks for whitelisted domain: {Domain}", domain);
                result.RiskLevel = "Low";
                return Task.FromResult(result);
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 1: IP Address in URL (common phishing tactic)
            // ═══════════════════════════════════════════════════════════════
            if (IPAddress.TryParse(domain, out var ipAddress))
            {
                // Don't block loopback/private IPs — they are commonly used for
                // local dev servers and OAuth callbacks (e.g. VS Code/GitHub sign-in).
                if (!IsLocalOrPrivateIp(ipAddress))
                {
                    result.IsMalicious = true;
                    result.ThreatType = "IpAddressUrl";
                    result.ThreatDetails = "URL uses raw public IP address instead of domain name";
                    result.RiskLevel = "High";
                    _logger.LogWarning("[IP] URL uses raw public IP address: {Domain}. BLOCKED.", domain);
                    return Task.FromResult(result);
                }

                _logger.LogDebug("[LOCAL] Allowing local/private IP URL: {Domain}", domain);
            }
            
            // ═══════════════════════════════════════════════════════════════
            // Check 2: Brand Impersonation Detection
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
                return Task.FromResult(result);
            }
            
            // No security issues detected
            _logger.LogDebug("[SAFE] Domain '{Domain}' passed security checks.", domain);
            return Task.FromResult(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in URL security analysis for '{Url}'. Failing open.", url);
            return Task.FromResult(result); // Fail-open - don't block on errors
        }
    }
    
    /// <summary>
    /// Detects brand impersonation in domain names.
    /// </summary>
    private (bool isSuspicious, List<string> brands, string reason) DetectBrandImpersonation(string domain, string fullUrl)
    {
        var detectedBrands = new List<string>();
        
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
        
        // Multiple brands = definitely suspicious (e.g., google-youtube-verify.com)
        if (detectedBrands.Count >= 2)
        {
            return (true, detectedBrands, 
                $"Multiple brand names detected: {string.Join(", ", detectedBrands)}");
        }
        
        // Single brand + suspicious keyword in DOMAIN = suspicious
        if (detectedBrands.Count == 1)
        {
            // Only check domain for suspicious keywords (not the full URL path)
            var hasSuspiciousKeyword = SuspiciousKeywords.Any(k => 
                domain.Contains(k, StringComparison.OrdinalIgnoreCase));
            
            if (hasSuspiciousKeyword)
            {
                return (true, detectedBrands,
                    $"Brand '{detectedBrands[0]}' with suspicious keyword in domain");
            }
            
            // Brand name with unusual TLD (e.g., paypal-login.tk)
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
        // Google owns the .gle TLD - any .gle domain is official Google (forms.gle, goo.gle, etc.)
        if (brand.Equals("google", StringComparison.OrdinalIgnoreCase) && domain.EndsWith(".gle", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        
        // Check if domain IS the brand's official domain or a subdomain
        var officialPatterns = new[]
        {
            $"{brand}.com", $"{brand}.org", $"{brand}.net", $"{brand}.io",
            $"{brand}.co", $"{brand}.gle", $"{brand}.ly",
            $"www.{brand}.com", $"www.{brand}.org"
        };
        
        // Direct match or subdomain of official domain
        return officialPatterns.Any(p => domain.Equals(p, StringComparison.OrdinalIgnoreCase)) ||
               domain.EndsWith($".{brand}.com", StringComparison.OrdinalIgnoreCase) ||
               domain.EndsWith($".{brand}.co", StringComparison.OrdinalIgnoreCase) ||
               domain.EndsWith($".{brand}.io", StringComparison.OrdinalIgnoreCase) ||
               domain.EndsWith($".{brand}.gle", StringComparison.OrdinalIgnoreCase);
    }
    
    /// <summary>
    /// Extracts TLD from domain.
    /// </summary>
    private string GetTld(string domain)
    {
        var lastDot = domain.LastIndexOf('.');
        return lastDot >= 0 ? domain[lastDot..] : "";
    }

    private static bool IsLocalOrPrivateIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();

            // 0.0.0.0/8 (includes 0.0.0.0)
            if (bytes[0] == 0) return true;

            // 10.0.0.0/8
            if (bytes[0] == 10) return true;

            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;

            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;

            // 100.64.0.0/10 (carrier-grade NAT)
            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return true;

            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal) return true;

            // Unique local fc00::/7
            var bytes = ip.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC) return true;

            return false;
        }

        return false;
    }
}
