using System;
using System.Collections.Generic;
using System.Linq;

namespace LinkShield.Core;

/// <summary>
/// Service for managing trusted/whitelisted domains.
/// These are legitimate services that use short URLs or random-looking paths
/// but are known to be safe (e.g., Google Forms, Amazon short links, etc.)
/// 
/// IMPORTANT: Hosting platforms (vercel.app, github.io, etc.) are NOT trusted
/// because anyone can host phishing sites on them. Only first-party domains
/// from major companies are trusted.
/// </summary>
public static class TrustedDomainsService
{
    /// <summary>
    /// Trusted short URL services and their official domains.
    /// These services intentionally use random-looking URLs.
    /// 
    /// NOTE: Does NOT include hosting platforms where users can deploy arbitrary content:
    ///   - vercel.app, netlify.app, github.io, herokuapp.com, pages.dev, etc.
    /// These are frequently abused by phishers and must go through blocklist checks.
    /// </summary>
    private static readonly HashSet<string> TrustedShortUrlDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        // Google services (Google owns .gle TLD)
        "forms.gle",
        "goo.gle",
        "g.co",
        "google.com",
        "docs.google.com",
        "drive.google.com",
        "meet.google.com",
        "mail.google.com",
        "calendar.google.com",
        "youtube.com",
        "youtu.be",
        
        // Amazon short links
        "amzn.in",
        "amzn.to",
        "amzn.eu",
        "amzn.asia",
        "a.co",
        "amazon.com",
        "amazon.in",
        "amazon.co.uk",
        "amazon.de",
        "amazon.fr",
        "amazon.es",
        "amazon.it",
        "amazon.ca",
        "amazon.com.au",
        
        // Microsoft services
        "microsoft.com",
        "office.com",
        "live.com",
        "outlook.com",
        "onedrive.live.com",
        "sharepoint.com",
        "1drv.ms",
        "aka.ms",
        "msft.it",
        
        // Apple services
        "apple.com",
        "icloud.com",
        "apple.co",
        
        // Meta/Facebook services
        "facebook.com",
        "fb.com",
        "fb.me",
        "m.me",
        "instagram.com",
        "instagr.am",
        "whatsapp.com",
        "wa.me",
        
        // Twitter/X
        "twitter.com",
        "t.co",
        "x.com",
        
        // LinkedIn
        "linkedin.com",
        "lnkd.in",
        
        // GitHub (main site only, NOT github.io which is user content)
        "github.com",
        "githubusercontent.com",
        "git.io",
        
        // Popular URL shorteners (legitimate services)
        "bit.ly",
        "bitly.com",
        "tinyurl.com",
        "ow.ly",
        "buff.ly",
        "rebrand.ly",
        "short.io",
        "bl.ink",
        "cutt.ly",
        
        // Other major services (first-party only)
        "dropbox.com",
        "db.tt",
        "slack.com",
        "zoom.us",
        "discord.com",
        "discord.gg",
        "reddit.com",
        "redd.it",
        "spotify.com",
        "spoti.fi",
        "netflix.com",
        "twitch.tv",
        "medium.com",
        
        // E-commerce
        "ebay.com",
        "ebay.to",
        "etsy.com",
        "etsy.me",
        "shopify.com",
        "shop.app",
        
        // Payment services
        "paypal.com",
        "paypal.me",
        "venmo.com",
        "stripe.com",
        "cash.app",
        
        // News/Media
        "nytimes.com",
        "nyti.ms",
        "washingtonpost.com",
        "wapo.st",
        "bbc.com",
        "bbc.co.uk",
        "bbc.in",
        "cnn.com",
        "cnn.it",
        "reuters.com",
        "reut.rs",
        
        // File sharing
        "wetransfer.com",
        "we.tl",
        "mediafire.com",
        "mega.nz",
        
        // Education
        "coursera.org",
        "udemy.com",
        "edx.org",
        "khanacademy.org",
        
        // Developer tools (first-party only, NOT hosting platforms)
        "stackoverflow.com",
        "npmjs.com",
        "pypi.org",
        "nuget.org",
        "hub.docker.com",
        "cloudflare.com",
        
        // Communication
        "telegram.org",
        "t.me",
        "signal.org",
        "skype.com"
        
        // REMOVED - These are hosting platforms that phishers abuse:
        // "vercel.app",      <- Phishing site: ghilngy.vercel.app
        // "netlify.app",     <- Anyone can deploy
        // "herokuapp.com",   <- Anyone can deploy
        // "github.io",       <- User Pages, anyone can deploy
        // "pages.dev",       <- Cloudflare Pages, anyone can deploy
        // "azurewebsites.net" <- Azure App Service, anyone can deploy
    };
    
    /// <summary>
    /// Trusted TLDs owned by specific companies.
    /// Any domain ending with these TLDs is considered trusted.
    /// </summary>
    private static readonly Dictionary<string, string> TrustedBrandTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        { ".gle", "Google" },       // Google owns .gle TLD (goo.gle, forms.gle, etc.)
        { ".google", "Google" },    // .google TLD
        { ".youtube", "Google" },   // .youtube TLD
        { ".android", "Google" },   // .android TLD
        { ".chrome", "Google" },    // .chrome TLD
        { ".apple", "Apple" },      // .apple TLD
        { ".microsoft", "Microsoft" }, // .microsoft TLD
        { ".azure", "Microsoft" },  // .azure TLD
        { ".amazon", "Amazon" },    // .amazon TLD
        { ".aws", "Amazon" },       // .aws TLD
        { ".xbox", "Microsoft" },   // .xbox TLD
        { ".windows", "Microsoft" },// .windows TLD
    };

    /// <summary>
    /// Checks if a domain is in the trusted whitelist.
    /// </summary>
    /// <param name="domain">The domain to check (e.g., "forms.gle", "amzn.in")</param>
    /// <returns>True if the domain is trusted</returns>
    public static bool IsTrustedDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return false;
            
        domain = domain.ToLowerInvariant();
        if (domain.StartsWith("www."))
            domain = domain[4..];
        
        // Direct match
        if (TrustedShortUrlDomains.Contains(domain))
            return true;
        
        // Check if it's a subdomain of a trusted domain
        foreach (var trusted in TrustedShortUrlDomains)
        {
            if (domain.EndsWith($".{trusted}", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        
        // Check trusted brand TLDs
        foreach (var tld in TrustedBrandTlds.Keys)
        {
            if (domain.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        
        return false;
    }
    
    /// <summary>
    /// Gets the brand name if the domain uses a trusted brand TLD.
    /// </summary>
    public static string? GetTrustedBrandForDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return null;
            
        foreach (var kvp in TrustedBrandTlds)
        {
            if (domain.EndsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                return kvp.Value;
        }
        
        return null;
    }
    
    /// <summary>
    /// Gets all trusted domains (for debugging/display).
    /// </summary>
    public static IReadOnlyCollection<string> GetAllTrustedDomains() => TrustedShortUrlDomains;
    
    /// <summary>
    /// Gets all trusted brand TLDs (for debugging/display).
    /// </summary>
    public static IReadOnlyDictionary<string, string> GetTrustedBrandTlds() => TrustedBrandTlds;
}
