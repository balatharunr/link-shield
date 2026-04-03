// Quick test to verify ML integration
// Run with: dotnet run

using LinkShield.Core;
using Microsoft.Extensions.Logging;

var loggerFactory = LoggerFactory.Create(b => {
    b.AddConsole();
    b.SetMinimumLevel(LogLevel.Debug);
});

Console.WriteLine("=".PadRight(60, '='));
Console.WriteLine("LinkShield ML Integration Test");
Console.WriteLine("=".PadRight(60, '='));

// Initialize ML scorer
Console.WriteLine("\n[1] Loading ML Model...");
try
{
    using var mlScorer = new LexicalMlScorer(loggerFactory.CreateLogger<LexicalMlScorer>());
    Console.WriteLine("    ✓ ML Model loaded successfully!");

    // Test URLs
    var testUrls = new (string Url, string Expected)[]
    {
        ("https://www.google.com/search?q=test", "SAFE"),
        ("https://github.com/microsoft/vscode", "SAFE"),
        ("https://www.amazon.com/dp/B08N5WRWNW", "SAFE"),
        ("http://192.168.1.1/paypal/login.php", "PHISHING"),
        ("https://verify-your-paypal-account.tk/signin", "PHISHING"),
        ("https://amazon-account-suspended.info/verify", "PHISHING"),
        ("https://secure-login.paypal.com.verification-center.tk/signin", "PHISHING"),
        ("https://login-microsoft-0ffice365.com/signin.aspx?session=expired", "PHISHING"),
    };

    Console.WriteLine("\n[2] Testing URLs...\n");
    Console.WriteLine($"{"URL",-55} {"Score",-10} {"Result",-12} {"Expected",-10} {"Status"}");
    Console.WriteLine(new string('-', 100));

    int passed = 0, failed = 0;
    foreach (var (url, expected) in testUrls)
    {
        var score = mlScorer.GetThreatScore(url);
        var result = score >= 0.85f ? "PHISHING" : (score >= 0.5f ? "SUSPICIOUS" : "SAFE");
        var isCorrect = (result == "PHISHING" && expected == "PHISHING") ||
                       (result != "PHISHING" && expected == "SAFE");
        
        var status = isCorrect ? "✓ PASS" : "✗ FAIL";
        if (isCorrect) passed++; else failed++;
        
        var displayUrl = url.Length > 53 ? url[..50] + "..." : url;
        Console.WriteLine($"{displayUrl,-55} {score,7:P1}   {result,-12} {expected,-10} {status}");
    }

    Console.WriteLine(new string('-', 100));
    Console.WriteLine($"\nResults: {passed} passed, {failed} failed");
    
    Console.WriteLine("\n[3] Testing Full Analyzer Pipeline...");
    
    // Initialize full analyzer
    var threatDb = new ThreatDatabaseService(loggerFactory.CreateLogger<ThreatDatabaseService>());
    await threatDb.EnsureDatabaseAsync();
    
    var analyzer = new SqliteUrlAnalyzer(
        threatDb,
        new[] { "malware.test.com" }, // Bootstrap blocklist
        loggerFactory.CreateLogger<SqliteUrlAnalyzer>(),
        mlScorer
    );
    
    // Test the full pipeline
    var pipelineTests = new[]
    {
        ("https://malware.test.com/evil", true, "Bootstrap"),      // Should be blocked by bootstrap
        ("https://www.google.com", false, "Safe"),                 // Should pass all checks
        ("https://verify-your-paypal-account.tk/signin", true, "ML"), // Should be blocked by ML
    };
    
    Console.WriteLine($"\n{"URL",-55} {"Blocked?",-10} {"Source"}");
    Console.WriteLine(new string('-', 80));
    
    foreach (var (url, shouldBlock, source) in pipelineTests)
    {
        var isBlocked = await analyzer.IsMaliciousAsync(url);
        var displayUrl = url.Length > 53 ? url[..50] + "..." : url;
        var status = isBlocked == shouldBlock ? "✓" : "✗";
        Console.WriteLine($"{status} {displayUrl,-53} {isBlocked,-10} {source}");
    }
    
    Console.WriteLine("\n" + "=".PadRight(60, '='));
    Console.WriteLine("ML Integration Test Complete!");
    Console.WriteLine("=".PadRight(60, '='));
}
catch (Exception ex)
{
    Console.WriteLine($"    ✗ Error: {ex.Message}");
    Console.WriteLine(ex.StackTrace);
}
