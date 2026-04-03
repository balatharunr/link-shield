using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LinkShield.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LinkShield.Service;

/// <summary>
/// Background worker that silently syncs the local threat database with
/// OpenPhish and PhishTank feeds every 24 hours. Handles network failures gracefully.
/// </summary>
public class ThreatFeedSyncWorker : BackgroundService
{
    private readonly ILogger<ThreatFeedSyncWorker> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ThreatDatabaseService _threatDb;

    private static readonly TimeSpan SyncInterval = TimeSpan.FromHours(24);

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
            await SyncAllFeedsAsync(stoppingToken);

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

    private async Task SyncAllFeedsAsync(CancellationToken ct)
    {
        _logger.LogInformation("Starting threat feed sync...");

        // Sync from multiple sources in parallel
        var openPhishTask = SyncOpenPhishAsync(ct);
        var phishTankTask = SyncPhishTankAsync(ct);

        await Task.WhenAll(openPhishTask, phishTankTask);

        var total = await _threatDb.GetDomainCountAsync();
        _logger.LogInformation("Threat feed sync complete. Total domains in DB: {Total}.", total);
    }

    private async Task SyncOpenPhishAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("OpenPhish");
            client.Timeout = TimeSpan.FromSeconds(30);

            var response = await client.GetAsync("https://openphish.com/feed.txt", ct);
            response.EnsureSuccessStatusCode();

            var feedContent = await response.Content.ReadAsStringAsync(ct);
            var domains = ParseFeedToDomains(feedContent);

            var inserted = await _threatDb.BulkUpsertAsync(domains);
            _logger.LogInformation("[OpenPhish] Synced {Count} domains, added {Inserted} new.", domains.Count, inserted);
        }
        catch (TaskCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OpenPhish] Failed to sync feed. Will retry next cycle.");
        }
    }

    private async Task SyncPhishTankAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("PhishTank");
            client.Timeout = TimeSpan.FromMinutes(2);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://data.phishtank.com/data/online-valid.json.gz");
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

            var urls = phishEntries
                .Where(e => e.Verified == "yes" || e.Verified == "true" || e.Verified == "1")
                .Select(e => e.Url)
                .Where(u => !string.IsNullOrEmpty(u))
                .ToList();

            var domains = urls
                .Where(url => Uri.TryCreate(url, UriKind.Absolute, out _))
                .Select(url => new Uri(url!).Host.ToLowerInvariant())
                .Where(host => !string.IsNullOrEmpty(host))
                .Distinct()
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var inserted = await _threatDb.BulkUpsertAsync(domains);
            _logger.LogInformation("[PhishTank] Synced {Count} verified URLs, added {Inserted} new domains.", urls.Count, inserted);
        }
        catch (TaskCanceledException)
        {
            throw;
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
        {
            _logger.LogWarning("[PhishTank] Rate limited. Will retry next cycle.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[PhishTank] Failed to sync feed. Will retry next cycle.");
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
                var cleaned = trimmed.ToLowerInvariant().Trim('/');
                if (!string.IsNullOrWhiteSpace(cleaned))
                {
                    domains.Add(cleaned);
                }
            }
        }

        return domains;
    }

    private class PhishTankEntry
    {
        public string? Url { get; set; }
        public string? Verified { get; set; }
        public string? Target { get; set; }
    }
}
