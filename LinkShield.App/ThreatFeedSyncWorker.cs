using LinkShield.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LinkShield.App;

/// <summary>
/// Background worker that periodically syncs threat feeds from OpenPhish and other sources.
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

            var client = _httpClientFactory.CreateClient("OpenPhish");
            client.Timeout = TimeSpan.FromSeconds(30);

            // OpenPhish free feed
            var openPhishUrl = "https://openphish.com/feed.txt";
            try
            {
                var response = await client.GetStringAsync(openPhishUrl, ct);
                var urls = response.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                
                // Extract domains from URLs
                var domains = urls
                    .Where(url => Uri.TryCreate(url, UriKind.Absolute, out _))
                    .Select(url => new Uri(url).Host)
                    .Where(host => !string.IsNullOrEmpty(host))
                    .Distinct()
                    .ToList();
                
                var inserted = await _threatDb.BulkUpsertAsync(domains);
                _logger.LogInformation("Synced {TotalUrls} URLs, added {NewDomains} new domains from OpenPhish", urls.Length, inserted);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sync OpenPhish feed");
            }

            _logger.LogInformation("Threat feed sync completed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during threat feed sync");
        }
    }
}
