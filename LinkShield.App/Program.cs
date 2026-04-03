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

                // Read bootstrap blocklist from config
                var bootstrapDomains = context.Configuration.GetSection("BootstrapBlocklist").Get<string[]>()
                                       ?? Array.Empty<string>();
                services.AddSingleton<IUrlAnalyzer>(sp =>
                    new SqliteUrlAnalyzer(
                        sp.GetRequiredService<ThreatDatabaseService>(),
                        bootstrapDomains,
                        sp.GetRequiredService<ILogger<SqliteUrlAnalyzer>>()));

                // HTTP client for threat feed downloads
                services.AddHttpClient("OpenPhish");

                // Background workers
                services.AddHostedService<ThreatFeedSyncWorker>();
            });

    private static void RunInterceptorMode(string url)
    {
        using var loggerFactory = LoggerFactory.Create(b =>
        {
            b.SetMinimumLevel(LogLevel.Warning); // Quieter for interceptor
        });
        var logger = loggerFactory.CreateLogger("Interceptor");

        try
        {
            var threatDb = new ThreatDatabaseService(
                loggerFactory.CreateLogger<ThreatDatabaseService>());
            threatDb.EnsureDatabaseAsync().GetAwaiter().GetResult();

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

            var isMalicious = analyzer.IsMaliciousAsync(url).GetAwaiter().GetResult();
            
            // Log detection to history
            var historyService = new DetectionHistoryService();
            historyService.LogDetection(url, isMalicious);
            
            if (isMalicious)
            {
                logger.LogWarning("BLOCKED: {Url}", url);
                ShowBlockedNotification(url);
                return;
            }

            LaunchInRealBrowser(url, logger);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing URL. Failing open.");
            try
            {
                LaunchInRealBrowser(url, logger);
            }
            catch
            {
                try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
            }
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

    private static void ShowBlockedNotification(string url)
    {
        var safeUrl = url.Replace("'", "''").Replace("\"", "`\"");
        if (safeUrl.Length > 150) safeUrl = safeUrl[..150] + "...";

        var psScript = @$"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($template.CreateTextNode('🛡️ LinkShield: Threat Blocked')) > $null
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
        catch { }
    }
}
