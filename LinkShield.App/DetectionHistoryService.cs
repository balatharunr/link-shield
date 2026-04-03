using System.Text.Json;

namespace LinkShield.App;

/// <summary>
/// Service for tracking URL detection history and analytics.
/// </summary>
public class DetectionHistoryService
{
    private readonly string _historyFilePath;
    private readonly object _lock = new();
    private List<DetectionRecord> _history = new();
    
    public DetectionHistoryService()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var linkShieldDir = Path.Combine(appData, "LinkShield");
        Directory.CreateDirectory(linkShieldDir);
        _historyFilePath = Path.Combine(linkShieldDir, "detection_history.json");
        LoadHistory();
    }

    public void LogDetection(string url, bool wasBlocked, string? threatType = null)
    {
        lock (_lock)
        {
            var record = new DetectionRecord
            {
                Id = Guid.NewGuid().ToString(),
                Url = url,
                Domain = TryGetDomain(url),
                WasBlocked = wasBlocked,
                ThreatType = threatType ?? (wasBlocked ? "Malicious URL" : "Safe"),
                DetectedAt = DateTime.UtcNow
            };
            
            _history.Insert(0, record);
            
            // Keep only last 1000 records
            if (_history.Count > 1000)
            {
                _history = _history.Take(1000).ToList();
            }
            
            SaveHistory();
        }
    }

    public IReadOnlyList<DetectionRecord> GetRecentDetections(int count = 50)
    {
        lock (_lock)
        {
            // Reload from file to pick up detections from interceptor process
            LoadHistory();
            return _history.Take(count).ToList();
        }
    }

    public AnalyticsSummary GetAnalytics()
    {
        lock (_lock)
        {
            // Reload from file to pick up detections from interceptor process
            LoadHistory();
            
            var now = DateTime.UtcNow;
            var today = _history.Where(h => h.DetectedAt.Date == now.Date).ToList();
            var thisWeek = _history.Where(h => h.DetectedAt >= now.AddDays(-7)).ToList();
            var thisMonth = _history.Where(h => h.DetectedAt >= now.AddDays(-30)).ToList();

            return new AnalyticsSummary
            {
                TotalScanned = _history.Count,
                TotalBlocked = _history.Count(h => h.WasBlocked),
                TotalSafe = _history.Count(h => !h.WasBlocked),
                
                TodayScanned = today.Count,
                TodayBlocked = today.Count(h => h.WasBlocked),
                
                WeekScanned = thisWeek.Count,
                WeekBlocked = thisWeek.Count(h => h.WasBlocked),
                
                MonthScanned = thisMonth.Count,
                MonthBlocked = thisMonth.Count(h => h.WasBlocked),
                
                TopBlockedDomains = _history
                    .Where(h => h.WasBlocked && !string.IsNullOrEmpty(h.Domain))
                    .GroupBy(h => h.Domain)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .Select(g => new DomainStat { Domain = g.Key!, Count = g.Count() })
                    .ToList()
            };
        }
    }

    public void ClearHistory()
    {
        lock (_lock)
        {
            _history.Clear();
            SaveHistory();
        }
    }

    private void LoadHistory()
    {
        try
        {
            if (File.Exists(_historyFilePath))
            {
                var json = File.ReadAllText(_historyFilePath);
                _history = JsonSerializer.Deserialize<List<DetectionRecord>>(json) ?? new();
            }
        }
        catch
        {
            _history = new();
        }
    }

    private void SaveHistory()
    {
        try
        {
            var json = JsonSerializer.Serialize(_history, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_historyFilePath, json);
        }
        catch { }
    }

    private static string? TryGetDomain(string url)
    {
        try
        {
            return new Uri(url).Host;
        }
        catch
        {
            return null;
        }
    }
}

public class DetectionRecord
{
    public string Id { get; set; } = "";
    public string Url { get; set; } = "";
    public string? Domain { get; set; }
    public bool WasBlocked { get; set; }
    public string ThreatType { get; set; } = "";
    public DateTime DetectedAt { get; set; }
}

public class AnalyticsSummary
{
    public int TotalScanned { get; set; }
    public int TotalBlocked { get; set; }
    public int TotalSafe { get; set; }
    
    public int TodayScanned { get; set; }
    public int TodayBlocked { get; set; }
    
    public int WeekScanned { get; set; }
    public int WeekBlocked { get; set; }
    
    public int MonthScanned { get; set; }
    public int MonthBlocked { get; set; }
    
    public List<DomainStat> TopBlockedDomains { get; set; } = new();
    
    public double BlockRate => TotalScanned > 0 ? (double)TotalBlocked / TotalScanned * 100 : 0;
}

public class DomainStat
{
    public string Domain { get; set; } = "";
    public int Count { get; set; }
}
