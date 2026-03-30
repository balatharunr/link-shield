using System.Diagnostics;
using LinkShield.Core;
using LinkShield.Service;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// ======================================================================
// LinkShield — "Split Personality" Entry Point
//
// Prong 1 (Interceptor Mode): args[0] is a URL -> analyze, block or forward, exit.
// Prong 2 (Daemon Mode):      no URL arg -> start background services.
// ======================================================================

if (args.Length > 0 && Uri.TryCreate(args[0], UriKind.Absolute, out var parsedUri)
                    && (parsedUri.Scheme == "http" || parsedUri.Scheme == "https"))
{
    // ── INTERCEPTOR FAST-PATH ──────────────────────────────────────
    await RunInterceptorAsync(args[0]);
    return;
}

// ── DAEMON MODE ────────────────────────────────────────────────────
await RunDaemonAsync(args);

// ===================================================================
// Interceptor Mode Implementation
// ===================================================================
static async Task RunInterceptorAsync(string url)
{
    using var loggerFactory = LoggerFactory.Create(b =>
    {
        b.AddConsole();
        b.SetMinimumLevel(LogLevel.Information);
    });
    var logger = loggerFactory.CreateLogger("Interceptor");

    try
    {
        // Lightweight setup — no full DI host needed for sub-20ms path
        var threatDb = new ThreatDatabaseService(
            loggerFactory.CreateLogger<ThreatDatabaseService>());
        await threatDb.EnsureDatabaseAsync();

        // Load bootstrap blocklist from appsettings.json
        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .Build();

        var bootstrapDomains = config.GetSection("BootstrapBlocklist").Get<string[]>()
                               ?? Array.Empty<string>();

        IUrlAnalyzer analyzer = new SqliteUrlAnalyzer(
            threatDb,
            bootstrapDomains,
            loggerFactory.CreateLogger<SqliteUrlAnalyzer>());

        logger.LogInformation("Intercepted URL: {Url}", url);

        var isMalicious = await analyzer.IsMaliciousAsync(url);
        if (isMalicious)
        {
            logger.LogWarning("BLOCKED malicious URL: {Url}", url);
            ShowBlockedToast(url);
            return; // Do NOT open the URL
        }

        logger.LogInformation("URL is safe. Forwarding to real browser...");
        LaunchInRealBrowser(url, loggerFactory.CreateLogger("BrowserLauncher"));
    }
    catch (Exception ex)
    {
        // Fail-open: if analysis fails, send to real browser anyway
        logger.LogError(ex, "Error processing URL. Failing open.");
        try
        {
            LaunchInRealBrowser(url, logger);
        }
        catch
        {
            // Absolute last resort — try shell execute
            try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
        }
    }
}

// ===================================================================
// Daemon Mode Implementation
// ===================================================================
static async Task RunDaemonAsync(string[] args)
{
    var builder = Host.CreateApplicationBuilder(args);

    // Core services
    builder.Services.AddSingleton<ThreatDatabaseService>();
    builder.Services.AddSingleton<WindowsRegistryManager>();

    // Read bootstrap blocklist from config and inject into SqliteUrlAnalyzer
    var bootstrapDomains = builder.Configuration.GetSection("BootstrapBlocklist").Get<string[]>()
                           ?? Array.Empty<string>();
    builder.Services.AddSingleton<IUrlAnalyzer>(sp =>
        new SqliteUrlAnalyzer(
            sp.GetRequiredService<ThreatDatabaseService>(),
            bootstrapDomains,
            sp.GetRequiredService<ILogger<SqliteUrlAnalyzer>>()));

    // HTTP client for threat feed downloads
    builder.Services.AddHttpClient("OpenPhish");

    // Background workers
    builder.Services.AddHostedService<ThreatFeedSyncWorker>();
    builder.Services.AddHostedService<DnsSinkholeWorker>();
    // NOTE: Removed the no-op Worker.cs — it did nothing useful.

    var host = builder.Build();

    // Register browser capability (runs once at launch)
    var registryManager = host.Services.GetRequiredService<WindowsRegistryManager>();
    var exePath = Environment.ProcessPath;
    if (!string.IsNullOrEmpty(exePath))
    {
        registryManager.RegisterAsBrowser(exePath);
    }

    await host.RunAsync();
}

// ===================================================================
// Helper: Launch URL in the user's REAL browser (not ourselves)
// ===================================================================
static void LaunchInRealBrowser(string url, ILogger logger)
{
    // Deviation from Gemini: We must NOT use UseShellExecute=true here because
    // if LinkShield IS the default browser, that would cause an infinite loop.
    // Instead, we read the backed-up real browser exe from the registry.

    using var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
    var registryManager = new WindowsRegistryManager(
        loggerFactory.CreateLogger<WindowsRegistryManager>());

    var browserPath = registryManager.GetPreviousBrowserPath();

    if (!string.IsNullOrEmpty(browserPath))
    {
        logger.LogInformation("Launching real browser: {Browser}", browserPath);
        Process.Start(new ProcessStartInfo
        {
            FileName = browserPath,
            Arguments = $"\"{url}\"",
            UseShellExecute = false
        });
    }
    else
    {
        // Fallback: try common browser paths
        var fallbacks = new[]
        {
            @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            @"C:\Program Files\Mozilla Firefox\firefox.exe",
            @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        };

        foreach (var fb in fallbacks)
        {
            if (File.Exists(fb))
            {
                logger.LogInformation("Fallback browser: {Browser}", fb);
                Process.Start(new ProcessStartInfo
                {
                    FileName = fb,
                    Arguments = $"\"{url}\"",
                    UseShellExecute = false
                });
                return;
            }
        }

        // Last resort: UseShellExecute with explorer.exe to avoid self-invoke
        logger.LogWarning("No known browser found. Using explorer.exe as launcher.");
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"\"{url}\"",
            UseShellExecute = false
        });
    }
}

// ===================================================================
// Helper: Show Windows Toast notification for blocked URLs
// ===================================================================
static void ShowBlockedToast(string url)
{
    // Sanitize the URL for PowerShell embedding (prevent injection)
    var safeUrl = url.Replace("'", "''").Replace("\"", "`\"");
    if (safeUrl.Length > 200) safeUrl = safeUrl[..200] + "...";

    var psScript = @$"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($template.CreateTextNode('LinkShield: Threat Blocked')) > $null
$textNodes.Item(1).AppendChild($template.CreateTextNode('Blocked: {safeUrl}')) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LinkShield')
$notifier.Show($toast)
";

    try
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{psScript}\"",
            CreateNoWindow = true,
            UseShellExecute = false
        };
        Process.Start(psi);
    }
    catch
    {
        // Toast is best-effort — don't let notification failure break blocking
    }
}
