using System.Diagnostics;
using LinkShield.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LinkShield.App;

static class Program
{
    private static IHost? _host;
    private static MainForm? _mainForm;
    
    [STAThread]
    static void Main(string[] args)
    {
        // Check if launched with URL argument (interceptor mode)
        if (args.Length > 0 && Uri.TryCreate(args[0], UriKind.Absolute, out var parsedUri)
                            && (parsedUri.Scheme == "http" || parsedUri.Scheme == "https"))
        {
            RunInterceptorMode(args[0]);
            return;
        }

        // Main application mode
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.SystemAware);

        // Ensure single instance
        using var mutex = new Mutex(true, "LinkShield_SingleInstance", out bool createdNew);
        if (!createdNew)
        {
            MessageBox.Show("LinkShield is already running.", "LinkShield", 
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        // Build and start the host
        _host = CreateHostBuilder(args).Build();
        
        // Register browser capability
        var registryManager = _host.Services.GetRequiredService<WindowsRegistryManager>();
        var exePath = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(exePath))
        {
            registryManager.RegisterAsBrowser(exePath);
        }

        // Start background services
        _host.StartAsync().GetAwaiter().GetResult();

        // Show welcome wizard on first run
        if (WelcomeForm.ShouldShowWelcome())
        {
            using var welcomeForm = new WelcomeForm(_host.Services);
            welcomeForm.ShowDialog();
        }

        // Run the main form
        _mainForm = new MainForm(_host.Services);
        Application.Run(_mainForm);

        // Cleanup
        _host.StopAsync().GetAwaiter().GetResult();
        _host.Dispose();
    }

    private static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureServices((context, services) =>
            {
                // Core services
                services.AddSingleton<ThreatDatabaseService>();
                services.AddSingleton<WindowsRegistryManager>();
                services.AddSingleton<DetectionHistoryService>();
                
                // Network state checker - DNS resolution (FIRST check in pipeline)
                services.AddSingleton<NetworkStateChecker>();
                
                // ML-based zero-day detection
                services.AddSingleton<LexicalMlScorer>();
                
                // Enhanced URL security checker (brand impersonation detection)
                services.AddSingleton<UrlSecurityChecker>();

                // Read bootstrap blocklist from config
                var bootstrapDomains = context.Configuration.GetSection("BootstrapBlocklist").Get<string[]>()
                                       ?? Array.Empty<string>();
                
                // URL Analyzer with all detection layers (new workflow order)
                services.AddSingleton<IUrlAnalyzer>(sp =>
                    new SqliteUrlAnalyzer(
                        sp.GetRequiredService<ThreatDatabaseService>(),
                        bootstrapDomains,
                        sp.GetRequiredService<ILogger<SqliteUrlAnalyzer>>(),
                        sp.GetRequiredService<LexicalMlScorer>(),
                        sp.GetRequiredService<UrlSecurityChecker>(),
                        sp.GetRequiredService<NetworkStateChecker>()));

                // HTTP client for threat feed downloads (OpenPhish, PhishTank, etc.)
                services.AddHttpClient("ThreatFeeds");

                // Background workers
                services.AddHostedService<ThreatFeedSyncWorker>();
            });

    private static void RunInterceptorMode(string url)
    {
        using var loggerFactory = LoggerFactory.Create(b =>
        {
            b.SetMinimumLevel(LogLevel.Debug); // More verbose for debugging
            b.AddConsole();
        });
        var logger = loggerFactory.CreateLogger("Interceptor");

        LexicalMlScorer? mlScorer = null;
        UrlSecurityChecker? securityChecker = null;
        NetworkStateChecker? networkChecker = null;
        
        try
        {
            logger.LogInformation("═══════════════════════════════════════════════════════");
            logger.LogInformation("LinkShield Interceptor - Analyzing URL");
            logger.LogInformation("URL: {Url}", url);
            logger.LogInformation("═══════════════════════════════════════════════════════");
            
            var threatDb = new ThreatDatabaseService(
                loggerFactory.CreateLogger<ThreatDatabaseService>());
            
            // Ensure database exists and load cache
            threatDb.EnsureDatabaseAsync().GetAwaiter().GetResult();
            
            // Log cache status for debugging
            var domainCount = threatDb.GetDomainCountAsync().GetAwaiter().GetResult();
            logger.LogInformation("Threat database loaded with {Count} domains", domainCount);

            var config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: true)
                .Build();

            var bootstrapDomains = config.GetSection("BootstrapBlocklist").Get<string[]>()
                                   ?? Array.Empty<string>();

            // Initialize network state checker FIRST - DNS is the first check
            networkChecker = new NetworkStateChecker(loggerFactory.CreateLogger<NetworkStateChecker>());
            
            // Initialize ML scorer for zero-day detection
            try
            {
                mlScorer = new LexicalMlScorer(loggerFactory.CreateLogger<LexicalMlScorer>());
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "ML scorer unavailable. Continuing without ML detection.");
            }
            
            // Initialize URL security checker for brand impersonation detection
            try
            {
                securityChecker = new UrlSecurityChecker(loggerFactory.CreateLogger<UrlSecurityChecker>());
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "URL security checker unavailable. Continuing without enhanced detection.");
            }

            // Create analyzer with all components including networkChecker
            var analyzer = new SqliteUrlAnalyzer(
                threatDb,
                bootstrapDomains,
                loggerFactory.CreateLogger<SqliteUrlAnalyzer>(),
                mlScorer,
                securityChecker,
                networkChecker);

            // Use the detailed analysis method
            var result = analyzer.AnalyzeUrlDetailedAsync(url).GetAwaiter().GetResult();
            
            var historyService = new DetectionHistoryService();
            
            // Handle dead links (DNS check failed)
            if (result.IsDead)
            {
                var domain = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : url;
                historyService.LogDetection(url, false, $"Dead Link: {result.ThreatDetails}", DetectionStatus.DeadLink);
                logger.LogWarning("══ DEAD LINK ══ Domain does not exist: {Details}", result.ThreatDetails);
                ShowDeadLinkNotification(domain);
                return;
            }
            
            // Handle malicious URLs
            if (result.IsMalicious)
            {
                historyService.LogDetection(url, true, $"{result.ThreatType}: {result.ThreatDetails}", DetectionStatus.Blocked);
                logger.LogWarning("══ BLOCKED ══ {ThreatType}: {Details}", result.ThreatType, result.ThreatDetails);
                ShowBlockedNotification(url, result.ThreatType);
                return;
            }
            
            // URL is safe - log and open in browser
            var mlScoreText = result.MlScore.HasValue ? $"{result.MlScore:P1}" : "N/A";
            var logMessage = result.IsTrusted 
                ? "Safe (Trusted Domain)" 
                : $"Safe (ML Score: {mlScoreText})";
            historyService.LogDetection(url, false, logMessage, DetectionStatus.Safe);
            
            logger.LogInformation("══ SAFE ══ Opening in browser{Trusted}", 
                result.IsTrusted ? " (Trusted Domain)" : "");

            LaunchInRealBrowser(url, logger);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing URL. Blocking for safety.");
            // On error, show notification instead of opening potentially dangerous URL
            ShowBlockedNotification(url, "Analysis Error - Blocked for Safety");
        }
        finally
        {
            mlScorer?.Dispose();
        }
    }

    private static void LaunchInRealBrowser(string url, ILogger logger)
    {
        using var loggerFactory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Warning));
        var registryManager = new WindowsRegistryManager(
            loggerFactory.CreateLogger<WindowsRegistryManager>());

        // Use effective browser (redirect preference > previous browser > fallback).
        // CRITICAL: never launch ourselves — LinkShield is the default handler, so
        // handing the URL back to LinkShield (directly or via explorer.exe) creates an
        // infinite launch loop that spawns processes forever.
        var browserPath = registryManager.GetEffectiveBrowserPath();

        if (TryLaunchBrowser(browserPath, url, logger))
            return;

        var fallbacks = new[]
        {
            @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            @"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            @"C:\Program Files\Mozilla Firefox\firefox.exe",
            @"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        };

        foreach (var fb in fallbacks)
        {
            if (TryLaunchBrowser(fb, url, logger))
                return;
        }

        // Last resort: do NOT fall back to explorer.exe / the shell — that re-enters
        // LinkShield (we are the default browser) and loops forever. Tell the user instead.
        logger.LogError("No real browser found to open safe URL '{Url}'. Aborting to avoid launch loop.", url);
        ShowToast("⚠️ LinkShield: No browser configured",
                  "Open Settings and pick a browser for safe links.");
    }

    /// <summary>
    /// Attempts to open the URL in the given browser executable.
    /// Refuses to launch LinkShield itself (prevents the interceptor loop) and
    /// verifies the executable exists. Returns true only if a process was started.
    /// </summary>
    private static bool TryLaunchBrowser(string? browserPath, string url, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(browserPath))
            return false;

        // Never re-launch ourselves under any name/location.
        if (browserPath.Contains("LinkShield", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning("Refusing to forward URL to a LinkShield executable ('{Path}') — would loop.", browserPath);
            return false;
        }

        if (!File.Exists(browserPath))
            return false;

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = browserPath,
                Arguments = $"\"{url}\"",
                UseShellExecute = false
            });
            return true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to launch browser '{Path}'", browserPath);
            return false;
        }
    }

    private static void ShowBlockedNotification(string url, string reason = "Threat Blocked")
    {
        var display = url.Length > 150 ? url[..150] + "..." : url;
        ShowToast($"🛡️ LinkShield: {reason}", $"Blocked: {display}");
    }

    private static void ShowDeadLinkNotification(string domain)
    {
        var display = domain.Length > 100 ? domain[..100] + "..." : domain;
        ShowToast("⚠️ LinkShield: Dead Link Detected", $"Server for {display} does not exist");
    }

    /// <summary>
    /// Shows a Windows toast notification. The two text lines are attacker-controllable
    /// (they contain the intercepted URL), so they are passed to PowerShell as ENVIRONMENT
    /// VARIABLES and the script itself is a fixed, base64-encoded constant. Nothing untrusted
    /// is ever interpolated into the script text — this closes the PowerShell-injection vector
    /// where a crafted malicious URL could execute code when it was blocked.
    /// </summary>
    private static void ShowToast(string line1, string line2)
    {
        // Fixed script — reads its text from $env:LS_LINE1 / $env:LS_LINE2 (never interpolated).
        const string script = @"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($template.CreateTextNode($env:LS_LINE1)) > $null
$textNodes.Item(1).AppendChild($template.CreateTextNode($env:LS_LINE2)) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
$toast.Tag = 'LinkShieldAlert'
$toast.Group = 'LinkShield'
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LinkShield')
try { [Windows.UI.Notifications.ToastNotificationManager]::History.Remove('LinkShieldAlert', 'LinkShield', 'LinkShield') } catch { }
$notifier.Show($toast)
";
        try
        {
            // -EncodedCommand takes base64(UTF-16LE) — no command-line quoting to escape.
            var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            // Untrusted text travels as data, not code.
            psi.EnvironmentVariables["LS_LINE1"] = line1;
            psi.EnvironmentVariables["LS_LINE2"] = line2;

            // Fire-and-forget - don't wait for PowerShell to complete
            Process.Start(psi);
        }
        catch { }
    }
}
