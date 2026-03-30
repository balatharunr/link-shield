using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LinkShield.Core;

public class DummyUrlAnalyzer : IUrlAnalyzer
{
    private readonly ILogger<DummyUrlAnalyzer> _logger;

    public DummyUrlAnalyzer(ILogger<DummyUrlAnalyzer> logger)
    {
        _logger = logger;
    }

    public Task<bool> IsMaliciousAsync(string url)
    {
        _logger.LogInformation("Analyzing URL: {Url}", url);
        
        // For testing purposes: simulate blocking a known malicious test URL
        if (url.Equals("https://malware.wicar.org/", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(true);
        }

        // Otherwise, hardcoded to false for Phase 1
        return Task.FromResult(false);
    }
}
