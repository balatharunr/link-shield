using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LinkShield.Core;

/// <summary>
/// Manages Windows Registry entries to register LinkShield as a browser capability
/// and safely detect/restore the user's previous default browser.
///
/// Deviation from Gemini's prompt: We do NOT attempt to programmatically SET
/// LinkShield as the default browser. Windows 10/11 blocks apps from doing this
/// via SetUserFTA / hash-based protection. Instead, we register the capability
/// and instruct the user to pick LinkShield in Settings > Default apps.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class WindowsRegistryManager
{
    private readonly ILogger<WindowsRegistryManager> _logger;

    private const string ProgId = "LinkShieldURL";
    private const string AppName = "LinkShield";
    private const string BackupRegistryPath = @"Software\LinkShield\BackupConfig";

    // Registry paths
    private const string ClassesPath = @"Software\Classes\" + ProgId;
    private const string ClientsPath = @"Software\Clients\StartMenuInternet\" + AppName;
    private const string RegisteredAppsPath = @"Software\RegisteredApplications";

    public WindowsRegistryManager(ILogger<WindowsRegistryManager> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Full ProgID + StartMenuInternet registration per Windows 10/11 requirements.
    /// Also backs up the current default browser before registration.
    /// </summary>
    public void RegisterAsBrowser(string executablePath)
    {
        try
        {
            _logger.LogInformation("Registering LinkShield as browser capability...");

            // Step 0: Backup the user's current default browser BEFORE we register
            BackupCurrentDefaultBrowser();

            // Step 1: Create ProgID under HKCU\Software\Classes\LinkShieldURL
            using (var progIdKey = Registry.CurrentUser.CreateSubKey(ClassesPath))
            {
                if (progIdKey == null) throw new InvalidOperationException("Failed to create ProgID key.");

                progIdKey.SetValue("", "LinkShield Protected URL Handler");

                // FTA hash requires EditFlags to mark as user-set
                progIdKey.SetValue("EditFlags", 2, RegistryValueKind.DWord);

                // DefaultIcon — use the exe's own icon
                using var iconKey = progIdKey.CreateSubKey("DefaultIcon");
                iconKey?.SetValue("", $"\"{executablePath}\",0");

                // shell\open\command — the interception command line
                using var commandKey = progIdKey.CreateSubKey(@"shell\open\command");
                commandKey?.SetValue("", $"\"{executablePath}\" \"%1\"");
            }

            // Step 2: Register under StartMenuInternet with full Capabilities
            using (var clientKey = Registry.CurrentUser.CreateSubKey(ClientsPath))
            {
                if (clientKey == null) throw new InvalidOperationException("Failed to create StartMenuInternet key.");

                clientKey.SetValue("", AppName);

                // shell\open\command for the main executable
                using var shellCmd = clientKey.CreateSubKey(@"shell\open\command");
                shellCmd?.SetValue("", $"\"{executablePath}\"");

                // Capabilities
                using var capKey = clientKey.CreateSubKey("Capabilities");
                if (capKey != null)
                {
                    capKey.SetValue("ApplicationName", "LinkShield");
                    capKey.SetValue("ApplicationDescription", "Privacy-first local URL threat interceptor");

                    // URL Associations
                    using var urlAssoc = capKey.CreateSubKey("URLAssociations");
                    urlAssoc?.SetValue("http", ProgId);
                    urlAssoc?.SetValue("https", ProgId);

                    // File Associations (for .htm/.html opened from disk)
                    using var fileAssoc = capKey.CreateSubKey("FileAssociations");
                    fileAssoc?.SetValue(".htm", ProgId);
                    fileAssoc?.SetValue(".html", ProgId);
                }
            }

            // Step 3: Register in HKCU\Software\RegisteredApplications
            using (var regApps = Registry.CurrentUser.CreateSubKey(RegisteredAppsPath))
            {
                regApps?.SetValue(AppName, @"Software\Clients\StartMenuInternet\LinkShield\Capabilities");
            }

            _logger.LogInformation("Registry registration complete.");

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("================================================================");
            Console.WriteLine(" LinkShield is registered as a browser capability.");
            Console.WriteLine(" ACTION REQUIRED to activate link interception:");
            Console.WriteLine("   1. Open Windows Settings -> Apps -> Default apps");
            Console.WriteLine("   2. Under 'Web browser', click the current browser");
            Console.WriteLine("   3. Select 'LinkShield' from the list");
            Console.WriteLine("================================================================");
            Console.ResetColor();
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register LinkShield as browser capability.");
        }
    }

    /// <summary>
    /// Removes all registry entries created by RegisterAsBrowser.
    /// </summary>
    public void UnregisterAsBrowser()
    {
        try
        {
            _logger.LogInformation("Unregistering LinkShield browser capabilities...");

            Registry.CurrentUser.DeleteSubKeyTree(ClassesPath, throwOnMissingSubKey: false);
            Registry.CurrentUser.DeleteSubKeyTree(ClientsPath, throwOnMissingSubKey: false);

            using var regApps = Registry.CurrentUser.OpenSubKey(RegisteredAppsPath, writable: true);
            regApps?.DeleteValue(AppName, throwOnMissingValue: false);

            _logger.LogInformation("Successfully unregistered.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to unregister browser capabilities.");
        }
    }

    /// <summary>
    /// Completely removes ALL LinkShield registry entries including backup config.
    /// Call this to fully clean up the system when uninstalling.
    /// </summary>
    public void CompleteUninstall()
    {
        try
        {
            _logger.LogInformation("Performing complete LinkShield uninstallation cleanup...");

            // 1. Remove browser registration
            UnregisterAsBrowser();

            // 2. Remove backup config
            Registry.CurrentUser.DeleteSubKeyTree(BackupRegistryPath, throwOnMissingSubKey: false);
            
            // Also try removing parent key if empty
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(@"Software\LinkShield", throwOnMissingSubKey: false);
            }
            catch { /* Parent may have other subkeys */ }

            // 3. Remove auto-start entry
            try
            {
                using var runKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: true);
                runKey?.DeleteValue(AppName, throwOnMissingValue: false);
            }
            catch { /* May not exist */ }

            _logger.LogInformation("Complete uninstall cleanup finished.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during complete uninstall cleanup.");
        }
    }

    /// <summary>
    /// Checks if LinkShield browser registration exists in the registry.
    /// </summary>
    public bool IsBrowserRegistered()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(ClassesPath);
            return key != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Detects the user's current default browser and saves it so LinkShield
    /// can forward safe URLs to it without causing an infinite loop.
    /// </summary>
    public void BackupCurrentDefaultBrowser()
    {
        try
        {
            var browserPath = DetectCurrentDefaultBrowserExe();
            if (string.IsNullOrEmpty(browserPath))
            {
                _logger.LogWarning("Could not detect current default browser. " +
                                   "Safe URLs will fall back to shell execution.");
                return;
            }

            // Don't backup ourselves
            var selfPath = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(selfPath) &&
                browserPath.Contains("LinkShield", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("Default browser is already LinkShield — skipping backup.");
                return;
            }

            using var backupKey = Registry.CurrentUser.CreateSubKey(BackupRegistryPath);
            backupKey?.SetValue("PreviousBrowserExe", browserPath);
            _logger.LogInformation("Backed up previous browser: {Path}", browserPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to backup current default browser.");
        }
    }

    /// <summary>
    /// Returns the executable path of the user's real (previous) browser,
    /// reading from the backup registry key. Returns null if not found.
    /// </summary>
    public string? GetPreviousBrowserPath()
    {
        try
        {
            using var backupKey = Registry.CurrentUser.OpenSubKey(BackupRegistryPath);
            var path = backupKey?.GetValue("PreviousBrowserExe") as string;

            if (!string.IsNullOrEmpty(path) && File.Exists(path.Trim('"')))
                return path.Trim('"');

            // Fallback: try detecting the current system browser
            var detected = DetectCurrentDefaultBrowserExe();
            if (!string.IsNullOrEmpty(detected) &&
                !detected.Contains("LinkShield", StringComparison.OrdinalIgnoreCase))
                return detected;

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read previous browser path.");
            return null;
        }
    }

    /// <summary>
    /// Gets the user's preferred redirect browser path.
    /// Returns null if auto-detect is selected (use original browser).
    /// </summary>
    public string? GetRedirectBrowserPath()
    {
        try
        {
            using var backupKey = Registry.CurrentUser.OpenSubKey(BackupRegistryPath);
            var path = backupKey?.GetValue("RedirectBrowserExe") as string;

            if (!string.IsNullOrEmpty(path) && File.Exists(path.Trim('"')))
                return path.Trim('"');

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read redirect browser path.");
            return null;
        }
    }

    /// <summary>
    /// Sets the user's preferred redirect browser path.
    /// Pass null to use auto-detect (original browser).
    /// </summary>
    public void SetRedirectBrowserPath(string? path)
    {
        try
        {
            using var backupKey = Registry.CurrentUser.CreateSubKey(BackupRegistryPath);
            if (backupKey == null) return;

            if (string.IsNullOrEmpty(path))
            {
                backupKey.DeleteValue("RedirectBrowserExe", throwOnMissingValue: false);
                _logger.LogInformation("Redirect browser set to auto-detect.");
            }
            else
            {
                backupKey.SetValue("RedirectBrowserExe", path);
                _logger.LogInformation("Redirect browser set to: {Path}", path);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to set redirect browser path.");
        }
    }

    /// <summary>
    /// Gets the effective browser path to use for redirecting safe URLs.
    /// Returns redirect browser if set, otherwise falls back to previous browser.
    /// </summary>
    public string? GetEffectiveBrowserPath()
    {
        var redirectPath = GetRedirectBrowserPath();
        if (!string.IsNullOrEmpty(redirectPath))
            return redirectPath;
        
        return GetPreviousBrowserPath();
    }

    /// <summary>
    /// Detects the exe path of the system's current default HTTP handler by reading
    /// the UserChoice ProgId and resolving it to a shell\open\command.
    /// </summary>
    private string? DetectCurrentDefaultBrowserExe()
    {
        try
        {
            // Windows stores the user's choice at:
            // HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice
            using var userChoice = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice");
            var progId = userChoice?.GetValue("ProgId") as string;

            if (string.IsNullOrEmpty(progId))
                return null;

            // Skip if it's already us
            if (progId.Contains("LinkShield", StringComparison.OrdinalIgnoreCase))
                return null;

            // Resolve ProgId -> shell\open\command
            using var cmdKey = Registry.ClassesRoot.OpenSubKey($@"{progId}\shell\open\command");
            var command = cmdKey?.GetValue("") as string;

            if (string.IsNullOrEmpty(command))
                return null;

            // Extract the exe path from the command string (e.g. "C:\...\chrome.exe" -- "%1")
            return ExtractExePathFromCommand(command);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to detect default browser from registry.");
            return null;
        }
    }

    /// <summary>
    /// Extracts the executable path from a registry command string like:
    ///   "C:\Program Files\Google\Chrome\Application\chrome.exe" -- "%1"
    /// </summary>
    private static string? ExtractExePathFromCommand(string command)
    {
        if (command.StartsWith('"'))
        {
            var endQuote = command.IndexOf('"', 1);
            if (endQuote > 1)
            {
                var path = command[1..endQuote];
                return File.Exists(path) ? path : null;
            }
        }
        else
        {
            // Unquoted — take up to first space
            var spaceIdx = command.IndexOf(' ');
            var path = spaceIdx > 0 ? command[..spaceIdx] : command;
            return File.Exists(path) ? path : null;
        }

        return null;
    }
}
