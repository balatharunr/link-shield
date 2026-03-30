using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using LinkShield.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LinkShield.Service;

/// <summary>
/// Background worker that silently syncs the local threat database with
/// the OpenPhish feed every 24 hours. Handles network failures gracefully.
/// </summary>
public class ThreatFeedSyncWorker : BackgroundService
{
    private readonly ILogger<ThreatFeedSyncWorker> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ThreatDatabaseService _threatDb;

    private static readonly TimeSpan SyncInterval = TimeSpan.FromHours(24);
    private const string OpenPhishFeedUrl = "https://openphish.com/feed.txt";

    public ThreatFeedSyncWorker(
        ILogger<ThreatFeedSyncWorker> logger,
        IHttpClientFactory httpClientFactory,
        ThreatDatabaseService threatDb)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _threatDb = threatDb;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Ensure the database is ready before first sync
        await _threatDb.EnsureDatabaseAsync();

        while (!stoppingToken.IsCancellationRequested)
        {
            await SyncFeedAsync(stoppingToken);

            try
            {
                _logger.LogInformation(
                    "Next threat feed sync in {Hours} hours.", SyncInterval.TotalHours);
                await Task.Delay(SyncInterval, stoppingToken);
            }
            catch (TaskCanceledException)
            {
                // Graceful shutdown
                break;
            }
        }
    }

    private async Task SyncFeedAsync(CancellationToken ct)
    {
        try
        {
            _logger.LogInformation("Starting threat feed sync from OpenPhish...");

            var client = _httpClientFactory.CreateClient("OpenPhish");
            client.Timeout = TimeSpan.FromSeconds(30);

            var response = await client.GetAsync(OpenPhishFeedUrl, ct);
            response.EnsureSuccessStatusCode();

            var feedContent = await response.Content.ReadAsStringAsync(ct);
            var domains = ParseFeedToDomains(feedContent);

            _logger.LogInformation("Parsed {Count} unique domains from OpenPhish feed.", domains.Count);

            var inserted = await _threatDb.BulkUpsertAsync(domains);
            var total = await _threatDb.GetDomainCountAsync();

            _logger.LogInformation(
                "Threat feed sync complete. Inserted: {Inserted}, Total in DB: {Total}.",
                inserted, total);
        }
        catch (TaskCanceledException)
        {
            // Shutting down — don't log as error
            throw;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex,
                "Network error during threat feed sync. " +
                "Will retry in {Hours} hours. (No Wi-Fi or feed unreachable.)",
                SyncInterval.TotalHours);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Unexpected error during threat feed sync. " +
                "Will retry in {Hours} hours.", SyncInterval.TotalHours);
        }
    }

    /// <summary>
    /// Parses the OpenPhish feed (one URL per line) and extracts unique domains.
    /// </summary>
    private static HashSet<string> ParseFeedToDomains(string feedContent)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in feedContent.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
                continue;

            // Each line is a full URL — extract the host
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
            {
                var host = uri.Host.ToLowerInvariant();
                if (!string.IsNullOrWhiteSpace(host))
                {
                    domains.Add(host);
                }
            }
            else
            {
                // If it's not a valid URL, try treating it as a bare domain
                var cleaned = trimmed.ToLowerInvariant().Trim('/');
                if (!string.IsNullOrWhiteSpace(cleaned))
                {
                    domains.Add(cleaned);
                }
            }
        }

        return domains;
    }
}
