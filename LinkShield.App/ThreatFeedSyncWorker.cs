using System.IO.Compression;
using System.Text.Json;
using LinkShield.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LinkShield.App;

/// <summary>
/// Background worker that periodically syncs threat feeds from OpenPhish, PhishTank, and other sources.
/// </summary>
public class ThreatFeedSyncWorker : BackgroundService
{
    private readonly ILogger<ThreatFeedSyncWorker> _logger;
    private readonly ThreatDatabaseService _threatDb;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeSpan _syncInterval = TimeSpan.FromHours(6);

    public ThreatFeedSyncWorker(
        ILogger<ThreatFeedSyncWorker> logger,
        ThreatDatabaseService threatDb,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _threatDb = threatDb;
        _httpClientFactory = httpClientFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial sync on startup
        await SyncThreatFeedsAsync(stoppingToken);

        // Periodic sync
        using var timer = new PeriodicTimer(_syncInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await SyncThreatFeedsAsync(stoppingToken);
        }
    }

    private async Task SyncThreatFeedsAsync(CancellationToken ct)
    {
        try
        {
            _logger.LogInformation("Starting threat feed sync...");
            await _threatDb.EnsureDatabaseAsync();

            // Sync from multiple sources in parallel for faster updates
            var openPhishTask = SyncOpenPhishAsync(ct);
            var phishTankTask = SyncPhishTankAsync(ct);

            await Task.WhenAll(openPhishTask, phishTankTask);

            var totalDomains = await _threatDb.GetDomainCountAsync();
            _logger.LogInformation("Threat feed sync completed. Total domains in database: {Count}", totalDomains);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during threat feed sync");
        }
    }

    /// <summary>
    /// Syncs the OpenPhish free feed (plain text URL list).
    /// </summary>
    private async Task SyncOpenPhishAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("ThreatFeeds");
            client.Timeout = TimeSpan.FromSeconds(30);

            var openPhishUrl = "https://openphish.com/feed.txt";
            var response = await client.GetStringAsync(openPhishUrl, ct);
            var urls = response.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var domains = ExtractDomainsFromUrls(urls);
            var inserted = await _threatDb.BulkUpsertAsync(domains);
            
            _logger.LogInformation("[OpenPhish] Synced {TotalUrls} URLs, added {NewDomains} new domains", urls.Length, inserted);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OpenPhish] Failed to sync feed");
        }
    }

    /// <summary>
    /// Syncs the PhishTank online valid phishing database.
    /// PhishTank provides a JSON database of verified phishing URLs.
    /// </summary>
    private async Task SyncPhishTankAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("ThreatFeeds");
            client.Timeout = TimeSpan.FromMinutes(2); // PhishTank DB can be large

            // PhishTank's free online database (JSON format, gzipped)
            // Note: For higher rate limits, register at phishtank.org and add API key
            var phishTankUrl = "http://data.phishtank.com/data/online-valid.json.gz";
            
            // Add user agent as required by PhishTank
            var request = new HttpRequestMessage(HttpMethod.Get, phishTankUrl);
            request.Headers.Add("User-Agent", "LinkShield/1.0 (phishtank-client)");
            
            var response = await client.SendAsync(request, ct);
            response.EnsureSuccessStatusCode();

            await using var compressedStream = await response.Content.ReadAsStreamAsync(ct);
            await using var decompressedStream = new GZipStream(compressedStream, CompressionMode.Decompress);
            using var reader = new StreamReader(decompressedStream);
            var json = await reader.ReadToEndAsync(ct);

            var phishEntries = JsonSerializer.Deserialize<List<PhishTankEntry>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (phishEntries == null || phishEntries.Count == 0)
            {
                _logger.LogWarning("[PhishTank] Empty or invalid response");
                return;
            }

            // Extract domains from PhishTank URLs
            var urls = phishEntries
                .Where(e => e.Verified == "yes" || e.Verified == "true" || e.Verified == "1")
                .Select(e => e.Url)
                .Where(u => !string.IsNullOrEmpty(u))
                .ToArray();

            var domains = ExtractDomainsFromUrls(urls!);
            var inserted = await _threatDb.BulkUpsertAsync(domains);
            
            _logger.LogInformation("[PhishTank] Synced {TotalUrls} verified URLs, added {NewDomains} new domains", urls.Length, inserted);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
        {
            _logger.LogWarning("[PhishTank] Rate limited. Will retry on next sync cycle.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[PhishTank] Failed to sync feed");
        }
    }

    /// <summary>
    /// Extracts unique domains from a list of URLs.
    /// Normalizes domains by removing 'www.' prefix and converting to lowercase.
    /// </summary>
    private static List<string> ExtractDomainsFromUrls(IEnumerable<string> urls)
    {
        return urls
            .Where(url => Uri.TryCreate(url, UriKind.Absolute, out _))
            .Select(url => {
                var host = new Uri(url).Host.ToLowerInvariant();
                // Remove www. prefix for consistent matching
                return host.StartsWith("www.") ? host[4..] : host;
            })
            .Where(host => !string.IsNullOrEmpty(host))
            .Distinct()
            .ToList();
    }

    /// <summary>
    /// PhishTank JSON entry structure.
    /// </summary>
    private class PhishTankEntry
    {
        public string? Url { get; set; }
        public string? Verified { get; set; }
        public string? Target { get; set; }
    }
}
