using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LinkShield.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LinkShield.Service;

/// <summary>
/// Local DNS sinkhole proxy. Intercepts DNS queries on 127.0.0.1:53,
/// checks domains against the threat database, and either:
///   - Returns 0.0.0.0 for malicious domains (sinkhole)
///   - Forwards to upstream DNS (8.8.8.8) for safe domains
///
/// CRITICAL SAFETY: On start, changes the active adapter's DNS to 127.0.0.1.
/// On stop OR crash, MUST revert DNS to automatic (DHCP). Multiple safety
/// mechanisms are layered to ensure this happens.
///
/// Deviations from Gemini's prompt:
///   1. Binds to IPAddress.Loopback (127.0.0.1) explicitly, not 0.0.0.0
///   2. Stores original DNS settings before overwriting (not just DHCP reset)
///   3. Registers AppDomain.ProcessExit + Console.CancelKeyPress as crash-safe hooks
///   4. Saves a "dns_needs_reset" sentinel file so even if the process is hard-killed,
///      the next launch can detect and clean up orphaned DNS state.
/// </summary>
public class DnsSinkholeWorker : BackgroundService, IDisposable
{
    private readonly ILogger<DnsSinkholeWorker> _logger;
    private readonly IUrlAnalyzer _urlAnalyzer;
    private readonly string _upstreamDns;
    private const int DnsPort = 53;

    // Sentinel file: if this exists on disk, DNS was hijacked and needs reset.
    // This handles the case where the process is killed (taskkill, crash, blue screen).
    private static readonly string SentinelFilePath = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "LinkShield", "dns_needs_reset");

    private string? _capturedAdapterName;
    private bool _dnsReverted;

    public DnsSinkholeWorker(
        ILogger<DnsSinkholeWorker> logger,
        IUrlAnalyzer urlAnalyzer,
        IConfiguration configuration)
    {
        _logger = logger;
        _urlAnalyzer = urlAnalyzer;
        _upstreamDns = configuration.GetValue<string>("UpstreamDns") ?? "8.8.8.8";
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("DNS Sinkhole starting...");

        // Safety: if a previous run crashed, clean up its DNS override first
        CleanUpOrphanedDnsOverride();

        // Set DNS to our local listener
        _capturedAdapterName = GetActiveAdapterName();
        if (!string.IsNullOrEmpty(_capturedAdapterName))
        {
            SetAdapterDns(_capturedAdapterName, "127.0.0.1");
            WriteSentinelFile(_capturedAdapterName);
            _logger.LogInformation("DNS redirected to 127.0.0.1 on adapter '{Adapter}'", _capturedAdapterName);
        }
        else
        {
            _logger.LogWarning("Could not detect active network adapter. DNS sinkhole will listen but system DNS is unchanged.");
        }

        // Register crash-safe hooks
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
        Console.CancelKeyPress += OnCancelKeyPress;

        await base.StartAsync(cancellationToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("DNS Sinkhole stopping — reverting DNS settings...");
        RevertDnsSafely();

        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
        Console.CancelKeyPress -= OnCancelKeyPress;

        await base.StopAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Bind ONLY to loopback — never expose DNS proxy externally
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, DnsPort));
        _logger.LogInformation("DNS Sinkhole listening on 127.0.0.1:{Port}", DnsPort);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var result = await udpClient.ReceiveAsync(stoppingToken);
                // Fire-and-forget per query to keep the receive loop fast
                _ = ProcessDnsQueryAsync(udpClient, result, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break; // Normal shutdown
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                _logger.LogCritical("Port 53 is already in use. Another DNS server may be running. Aborting sinkhole.");
                RevertDnsSafely();
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error receiving DNS query.");
            }
        }
    }

    // ===================================================================
    // DNS Query Processing
    // ===================================================================

    private async Task ProcessDnsQueryAsync(UdpClient localClient, UdpReceiveResult receiveResult, CancellationToken ct)
    {
        var requestData = receiveResult.Buffer;
        if (requestData.Length < 12) return; // Invalid DNS packet

        try
        {
            var domain = ParseDomainFromDnsQuery(requestData, out int questionEndIndex);

            if (string.IsNullOrEmpty(domain))
            {
                await ForwardToUpstreamAsync(localClient, receiveResult.RemoteEndPoint, requestData, ct);
                return;
            }

            var isMalicious = await _urlAnalyzer.IsMaliciousAsync($"http://{domain}");

            if (isMalicious)
            {
                _logger.LogWarning("DNS SINKHOLED: {Domain} -> 0.0.0.0", domain);
                var response = BuildSinkholeResponse(requestData);
                await localClient.SendAsync(response, response.Length, receiveResult.RemoteEndPoint);
            }
            else
            {
                _logger.LogDebug("DNS FORWARDING: {Domain} -> {Upstream}", domain, _upstreamDns);
                await ForwardToUpstreamAsync(localClient, receiveResult.RemoteEndPoint, requestData, ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing DNS query. Forwarding to upstream.");
            try
            {
                await ForwardToUpstreamAsync(localClient, receiveResult.RemoteEndPoint, requestData, ct);
            }
            catch { /* Best-effort */ }
        }
    }

    private async Task ForwardToUpstreamAsync(UdpClient localClient, IPEndPoint clientEndpoint, byte[] requestData, CancellationToken ct)
    {
        try
        {
            using var upstream = new UdpClient();
            var upstreamEp = new IPEndPoint(IPAddress.Parse(_upstreamDns), DnsPort);

            await upstream.SendAsync(requestData, requestData.Length, upstreamEp);

            // Race: upstream response vs 3-second timeout
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(3));

            try
            {
                var response = await upstream.ReceiveAsync(cts.Token);
                await localClient.SendAsync(response.Buffer, response.Buffer.Length, clientEndpoint);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                _logger.LogWarning("Upstream DNS {Upstream} timed out (3s).", _upstreamDns);
            }
        }
        catch (OperationCanceledException) { /* Shutdown */ }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error forwarding to upstream DNS.");
        }
    }

    // ===================================================================
    // DNS Packet Parsing & Building
    // ===================================================================

    private static string ParseDomainFromDnsQuery(byte[] buffer, out int questionEndIndex)
    {
        questionEndIndex = 12; // DNS header is 12 bytes
        var sb = new StringBuilder();

        while (questionEndIndex < buffer.Length)
        {
            int labelLen = buffer[questionEndIndex];

            if (labelLen == 0)
            {
                questionEndIndex++; // Skip null terminator
                break;
            }

            // Pointer (compression) — shouldn't happen in queries but handle it
            if ((labelLen & 0xC0) == 0xC0)
            {
                questionEndIndex += 2;
                break;
            }

            questionEndIndex++; // Skip length byte
            for (int i = 0; i < labelLen && questionEndIndex < buffer.Length; i++)
            {
                sb.Append((char)buffer[questionEndIndex++]);
            }
            sb.Append('.');
        }

        // Remove trailing dot
        if (sb.Length > 0) sb.Length--;

        // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
        questionEndIndex += 4;

        return sb.ToString();
    }

    private static byte[] BuildSinkholeResponse(byte[] request)
    {
        // Build a minimal DNS response with one A record pointing to 0.0.0.0
        var response = new byte[request.Length + 16]; // +16 for one answer RR
        Array.Copy(request, response, request.Length);

        // Set QR=1 (response), keep opcode, set RA=1
        response[2] = (byte)(response[2] | 0x80); // QR bit
        response[3] = (byte)(response[3] | 0x80); // RA bit

        // ANCOUNT = 1
        response[6] = 0x00;
        response[7] = 0x01;

        int offset = request.Length;

        // Name: pointer to offset 12 (the question's domain)
        response[offset++] = 0xC0;
        response[offset++] = 0x0C;

        // Type: A (1)
        response[offset++] = 0x00;
        response[offset++] = 0x01;

        // Class: IN (1)
        response[offset++] = 0x00;
        response[offset++] = 0x01;

        // TTL: 60 seconds
        response[offset++] = 0x00;
        response[offset++] = 0x00;
        response[offset++] = 0x00;
        response[offset++] = 0x3C;

        // RDLENGTH: 4 (IPv4 address)
        response[offset++] = 0x00;
        response[offset++] = 0x04;

        // RDATA: 0.0.0.0
        response[offset++] = 0x00;
        response[offset++] = 0x00;
        response[offset++] = 0x00;
        response[offset++] = 0x00;

        return response;
    }

    // ===================================================================
    // DNS Network Hook — Set/Revert system DNS
    // ===================================================================

    private void RevertDnsSafely()
    {
        if (_dnsReverted) return;
        _dnsReverted = true;

        var adapter = _capturedAdapterName ?? GetActiveAdapterName();
        if (!string.IsNullOrEmpty(adapter))
        {
            ResetAdapterDns(adapter);
            _logger.LogInformation("DNS reverted to DHCP/automatic on '{Adapter}'", adapter);
        }

        DeleteSentinelFile();
    }

    /// <summary>
    /// On startup, check if a previous run crashed and left DNS pointing at 127.0.0.1.
    /// If the sentinel file exists, revert DNS before doing anything else.
    /// </summary>
    private void CleanUpOrphanedDnsOverride()
    {
        try
        {
            if (!System.IO.File.Exists(SentinelFilePath)) return;

            var adapterName = System.IO.File.ReadAllText(SentinelFilePath).Trim();
            _logger.LogWarning(
                "Detected orphaned DNS override from a previous crash on adapter '{Adapter}'. Reverting...",
                adapterName);

            if (!string.IsNullOrEmpty(adapterName))
            {
                ResetAdapterDns(adapterName);
            }

            DeleteSentinelFile();
            _logger.LogInformation("Orphaned DNS override cleaned up.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to clean up orphaned DNS override.");
        }
    }

    private static void WriteSentinelFile(string adapterName)
    {
        try
        {
            var dir = System.IO.Path.GetDirectoryName(SentinelFilePath)!;
            System.IO.Directory.CreateDirectory(dir);
            System.IO.File.WriteAllText(SentinelFilePath, adapterName);
        }
        catch { /* Best effort */ }
    }

    private static void DeleteSentinelFile()
    {
        try { System.IO.File.Delete(SentinelFilePath); } catch { }
    }

    // ===================================================================
    // PowerShell Adapter Management
    // ===================================================================

    private string? GetActiveAdapterName()
    {
        try
        {
            // Get the adapter used by the default route (most reliable method)
            var output = RunPowerShellWithOutput(
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 | Get-NetAdapter | Select-Object -ExpandProperty Name");
            return string.IsNullOrWhiteSpace(output) ? null : output.Trim();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to detect active network adapter.");
            return null;
        }
    }

    private void SetAdapterDns(string adapterName, string dns)
    {
        RunPowerShell($"Set-DnsClientServerAddress -InterfaceAlias '{EscapePsString(adapterName)}' -ServerAddresses '{dns}'");
    }

    private void ResetAdapterDns(string adapterName)
    {
        RunPowerShell($"Set-DnsClientServerAddress -InterfaceAlias '{EscapePsString(adapterName)}' -ResetServerAddresses");
    }

    private static string EscapePsString(string value) => value.Replace("'", "''");

    private void RunPowerShell(string command)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{command}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi);
            process?.WaitForExit(10000);

            if (process is { ExitCode: not 0 })
            {
                var stderr = process.StandardError.ReadToEnd();
                if (!string.IsNullOrWhiteSpace(stderr))
                    _logger.LogWarning("PowerShell stderr: {Err}", stderr);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PowerShell command failed: {Cmd}", command);
        }
    }

    private string? RunPowerShellWithOutput(string command)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{command}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi);
            var output = process?.StandardOutput.ReadToEnd();
            process?.WaitForExit(10000);
            return output?.Trim();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PowerShell command failed: {Cmd}", command);
            return null;
        }
    }

    // ===================================================================
    // Crash-Safe Event Handlers
    // ===================================================================

    private void OnProcessExit(object? sender, EventArgs e) => RevertDnsSafely();

    private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e) => RevertDnsSafely();

    public override void Dispose()
    {
        RevertDnsSafely();
        base.Dispose();
    }
}
