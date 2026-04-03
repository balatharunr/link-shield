using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

/// <summary>
/// Result of DNS check with detailed information.
/// </summary>
public class DnsCheckResult
{
    /// <summary>Domain is alive and resolves to IP(s).</summary>
    public bool IsAlive { get; set; }
    
    /// <summary>The resolved IP addresses (if any).</summary>
    public IPAddress[]? ResolvedAddresses { get; set; }
    
    /// <summary>Error message if check failed.</summary>
    public string? ErrorMessage { get; set; }
    
    /// <summary>Whether the result was due to timeout (uncertain).</summary>
    public bool WasTimeout { get; set; }
}

/// <summary>
/// Network state checker for validating if domains are alive.
/// This is the FIRST check in the URL analysis pipeline.
/// 
/// If a domain doesn't resolve to an IP, it's a dead link and should not
/// be opened in the browser (would show ERR_NAME_NOT_RESOLVED).
/// </summary>
public class NetworkStateChecker
{
    private readonly ILogger<NetworkStateChecker> _logger;
    
    // Increased timeout for more reliable DNS resolution
    // 2 seconds is reasonable - DNS should respond quickly for valid domains
    private const int DnsTimeoutMs = 2000;

    public NetworkStateChecker(ILogger<NetworkStateChecker> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Checks if a domain resolves to an IP address (is alive).
    /// 
    /// Returns detailed result including:
    ///   - IsAlive: true if domain resolves to at least one IP
    ///   - ResolvedAddresses: the IP addresses if resolved
    ///   - WasTimeout: true if we couldn't determine due to timeout
    /// 
    /// IMPORTANT: This should be the FIRST check in the URL analysis flow.
    /// If domain doesn't exist, there's no point checking blocklists or ML.
    /// </summary>
    public async Task<DnsCheckResult> CheckDomainAsync(string domain)
    {
        var result = new DnsCheckResult();
        
        if (string.IsNullOrWhiteSpace(domain))
        {
            result.IsAlive = false;
            result.ErrorMessage = "Empty domain";
            return result;
        }

        try
        {
            using var cts = new CancellationTokenSource(DnsTimeoutMs);
            
            _logger.LogDebug("[DNS] Resolving '{Domain}'...", domain);
            
            // GetHostAddressesAsync with cancellation
            var addresses = await Dns.GetHostAddressesAsync(domain, cts.Token);
            
            if (addresses.Length > 0)
            {
                result.IsAlive = true;
                result.ResolvedAddresses = addresses;
                _logger.LogDebug("[DNS] Domain '{Domain}' resolved to {Count} IP(s): {Ip}", 
                    domain, addresses.Length, addresses[0]);
                return result;
            }
            
            // No addresses returned (unusual but possible)
            result.IsAlive = false;
            result.ErrorMessage = "No IP addresses returned";
            _logger.LogWarning("[DNS] Domain '{Domain}' returned no addresses - treating as DEAD", domain);
            return result;
        }
        catch (SocketException ex)
        {
            // NXDOMAIN or other DNS failure - domain definitely does not exist
            result.IsAlive = false;
            result.ErrorMessage = $"DNS Error: {ex.SocketErrorCode}";
            _logger.LogInformation("[DNS] Domain '{Domain}' is DEAD: {Error}", 
                domain, ex.SocketErrorCode);
            return result;
        }
        catch (OperationCanceledException)
        {
            // Timeout - uncertain, but likely dead or very slow
            result.IsAlive = false;
            result.WasTimeout = true;
            result.ErrorMessage = "DNS lookup timed out";
            _logger.LogWarning("[DNS] Timeout checking '{Domain}' after {Timeout}ms - treating as DEAD", 
                domain, DnsTimeoutMs);
            return result;
        }
        catch (Exception ex)
        {
            // Any other error - treat as dead
            result.IsAlive = false;
            result.ErrorMessage = ex.Message;
            _logger.LogWarning("[DNS] Error checking '{Domain}': {Error} - treating as DEAD", 
                domain, ex.Message);
            return result;
        }
    }

    /// <summary>
    /// Simple check that returns true/false for backward compatibility.
    /// </summary>
    public async Task<bool> IsDomainAliveAsync(string domain)
    {
        var result = await CheckDomainAsync(domain);
        return result.IsAlive;
    }

    /// <summary>
    /// Synchronous version for use in contexts where async is not available.
    /// </summary>
    public bool IsDomainAlive(string domain)
    {
        try
        {
            return IsDomainAliveAsync(domain).GetAwaiter().GetResult();
        }
        catch
        {
            return false; // Fail-closed for DNS check
        }
    }
}
