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

        // Use effective browser (redirect preference > previous browser > fallback)
        var browserPath = registryManager.GetEffectiveBrowserPath();

        if (!string.IsNullOrEmpty(browserPath))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = browserPath,
                Arguments = $"\"{url}\"",
                UseShellExecute = false
            });
        }
        else
        {
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
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = fb,
                        Arguments = $"\"{url}\"",
                        UseShellExecute = false
                    });
                    return;
                }
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{url}\"",
                UseShellExecute = false
            });
        }
    }

    private static void ShowBlockedNotification(string url, string reason = "Threat Blocked")
    {
        // Fire-and-forget notification that replaces any existing notification instantly
        // Uses ToastNotification with Tag to replace previous notifications
        var safeUrl = url.Replace("'", "''").Replace("\"", "`\"");
        if (safeUrl.Length > 150) safeUrl = safeUrl[..150] + "...";

        var psScript = @$"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($template.CreateTextNode('🛡️ LinkShield: {reason}')) > $null
$textNodes.Item(1).AppendChild($template.CreateTextNode('Blocked: {safeUrl}')) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
$toast.Tag = 'LinkShieldAlert'
$toast.Group = 'LinkShield'
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LinkShield')
# Remove any existing notification with same tag before showing new one
try {{ [Windows.UI.Notifications.ToastNotificationManager]::History.Remove('LinkShieldAlert', 'LinkShield', 'LinkShield') }} catch {{ }}
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
            // Fire-and-forget - don't wait for PowerShell to complete
            Process.Start(psi);
        }
        catch { }
    }
    
    private static void ShowDeadLinkNotification(string domain)
    {
        // Fire-and-forget notification that replaces any existing notification instantly
        var safeDomain = domain.Replace("'", "''").Replace("\"", "`\"");
        if (safeDomain.Length > 100) safeDomain = safeDomain[..100] + "...";

        var psScript = @$"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($template.CreateTextNode('⚠️ LinkShield: Dead Link Detected')) > $null
$textNodes.Item(1).AppendChild($template.CreateTextNode('Server for {safeDomain} does not exist')) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
$toast.Tag = 'LinkShieldAlert'
$toast.Group = 'LinkShield'
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LinkShield')
# Remove any existing notification with same tag before showing new one
try {{ [Windows.UI.Notifications.ToastNotificationManager]::History.Remove('LinkShieldAlert', 'LinkShield', 'LinkShield') }} catch {{ }}
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
            // Fire-and-forget - don't wait for PowerShell to complete
            Process.Start(psi);
        }
        catch { }
    }
}
