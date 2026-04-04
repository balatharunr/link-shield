using LinkShield.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;

namespace LinkShield.App;

public partial class SettingsForm : Form
{
    private readonly IServiceProvider _services;
    private readonly WindowsRegistryManager _registryManager;
    
    private CheckBox _autoStartCheckBox = null!;
    private CheckBox _notificationsCheckBox = null!;
    private Button _setDefaultBrowserBtn = null!;
    private Button _restoreDefaultBrowserBtn = null!;
    private Button _unregisterBtn = null!;
    private Label _currentBrowserLabel = null!;
    private ComboBox _redirectBrowserCombo = null!;
    private Label _redirectBrowserLabel = null!;
    private Label _registrationStatusLabel = null!;

    // List of detected browsers
    private List<BrowserInfo> _installedBrowsers = new();

    public SettingsForm(IServiceProvider services)
    {
        _services = services;
        _registryManager = services.GetRequiredService<WindowsRegistryManager>();
        
        DetectInstalledBrowsers();
        InitializeComponent();
        LoadSettings();
    }

    private void DetectInstalledBrowsers()
    {
        _installedBrowsers.Clear();
        
        var browserPaths = new (string Name, string[] Paths)[]
        {
            ("Google Chrome", new[] {
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")
            }),
            ("Microsoft Edge", new[] {
                @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                @"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
            }),
            ("Mozilla Firefox", new[] {
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                @"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
            }),
            ("Brave", new[] {
                @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                @"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe")
            }),
            ("Opera", new[] {
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Programs\Opera\launcher.exe"),
                @"C:\Program Files\Opera\launcher.exe"
            }),
            ("Vivaldi", new[] {
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe"),
                @"C:\Program Files\Vivaldi\Application\vivaldi.exe"
            }),
            ("Arc", new[] {
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Arc\Application\arc.exe")
            })
        };

        foreach (var (name, paths) in browserPaths)
        {
            foreach (var path in paths)
            {
                if (File.Exists(path))
                {
                    _installedBrowsers.Add(new BrowserInfo(name, path));
                    break; // Found this browser, move to next
                }
            }
        }
    }

    private void InitializeComponent()
    {
        Text = "Settings";
        Size = new Size(450, 550);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Color.FromArgb(28, 28, 28);
        ForeColor = Color.White;

        var titleLabel = new Label
        {
            Text = "⚙️ Settings",
            Font = new Font("Segoe UI", 16, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(20, 20),
            AutoSize = true
        };

        // Browser Settings Group
        var browserGroup = new GroupBox
        {
            Text = "Browser Integration",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(20, 60),
            Size = new Size(390, 230)
        };

        _currentBrowserLabel = new Label
        {
            Text = "Current default browser: Loading...",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.LightGray,
            Location = new Point(15, 28),
            AutoSize = true
        };

        _registrationStatusLabel = new Label
        {
            Text = "Registration: Checking...",
            Font = new Font("Segoe UI", 8),
            ForeColor = Color.Gray,
            Location = new Point(15, 48),
            AutoSize = true
        };

        _setDefaultBrowserBtn = new Button
        {
            Text = "Set LinkShield as Default Browser",
            Font = new Font("Segoe UI", 9),
            Size = new Size(220, 35),
            Location = new Point(15, 75),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(0, 120, 215),
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        _setDefaultBrowserBtn.FlatAppearance.BorderSize = 0;
        _setDefaultBrowserBtn.Click += OnSetDefaultBrowserClick;

        _restoreDefaultBrowserBtn = new Button
        {
            Text = "Restore Browser",
            Font = new Font("Segoe UI", 9),
            Size = new Size(100, 35),
            Location = new Point(245, 75),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(60, 60, 60),
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        _restoreDefaultBrowserBtn.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 80);
        _restoreDefaultBrowserBtn.Click += OnRestoreDefaultBrowserClick;

        _unregisterBtn = new Button
        {
            Text = "🗑️ Unregister",
            Font = new Font("Segoe UI", 9),
            Size = new Size(100, 35),
            Location = new Point(15, 115),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(180, 50, 50),
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        _unregisterBtn.FlatAppearance.BorderSize = 0;
        _unregisterBtn.Click += OnUnregisterClick;

        // Redirect browser selection
        _redirectBrowserLabel = new Label
        {
            Text = "Redirect safe URLs to:",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.White,
            Location = new Point(15, 160),
            AutoSize = true
        };

        _redirectBrowserCombo = new ComboBox
        {
            Font = new Font("Segoe UI", 9),
            Location = new Point(15, 183),
            Size = new Size(360, 28),
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = Color.FromArgb(45, 45, 45),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        
        // Add detected browsers to combo
        _redirectBrowserCombo.Items.Add("Auto-detect (use original browser)");
        foreach (var browser in _installedBrowsers)
        {
            _redirectBrowserCombo.Items.Add(browser.Name);
        }
        _redirectBrowserCombo.SelectedIndex = 0;
        _redirectBrowserCombo.SelectedIndexChanged += OnRedirectBrowserChanged;

        browserGroup.Controls.AddRange(new Control[] { 
            _currentBrowserLabel,
            _registrationStatusLabel,
            _setDefaultBrowserBtn, 
            _restoreDefaultBrowserBtn,
            _unregisterBtn,
            _redirectBrowserLabel,
            _redirectBrowserCombo
        });

        // General Settings Group
        var generalGroup = new GroupBox
        {
            Text = "General",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(20, 305),
            Size = new Size(390, 90)
        };

        _autoStartCheckBox = new CheckBox
        {
            Text = "Start with Windows",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.White,
            Location = new Point(15, 30),
            AutoSize = true,
            Checked = IsAutoStartEnabled()
        };
        _autoStartCheckBox.CheckedChanged += OnAutoStartChanged;

        _notificationsCheckBox = new CheckBox
        {
            Text = "Show notifications for blocked URLs",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.White,
            Location = new Point(15, 55),
            AutoSize = true,
            Checked = true
        };

        generalGroup.Controls.AddRange(new Control[] { _autoStartCheckBox, _notificationsCheckBox });

        // Info Label
        var infoLabel = new Label
        {
            Text = "💡 LinkShield intercepts URLs clicked from apps and checks\n     them before opening in your selected browser.",
            Font = new Font("Segoe UI", 8),
            ForeColor = Color.Gray,
            Location = new Point(20, 405),
            AutoSize = true
        };

        // Close button
        var closeBtn = new Button
        {
            Text = "Close",
            Font = new Font("Segoe UI", 10),
            Size = new Size(100, 35),
            Location = new Point(310, 460),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(50, 50, 50),
            ForeColor = Color.White,
            Cursor = Cursors.Hand,
            DialogResult = DialogResult.OK
        };
        closeBtn.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 80);
        closeBtn.Click += (s, e) => Close();  // Explicitly close the form

        Controls.AddRange(new Control[] { titleLabel, browserGroup, generalGroup, infoLabel, closeBtn });
    }

    private void LoadSettings()
    {
        // Load original browser info
        var previousBrowser = _registryManager.GetPreviousBrowserPath();
        if (!string.IsNullOrEmpty(previousBrowser))
        {
            var browserName = Path.GetFileNameWithoutExtension(previousBrowser);
            _currentBrowserLabel.Text = $"Original browser: {browserName}";
        }
        else
        {
            _currentBrowserLabel.Text = "No previous browser detected";
        }

        // Load registration status
        UpdateRegistrationStatus();

        // Load redirect browser selection
        var savedRedirectBrowser = _registryManager.GetRedirectBrowserPath();
        if (!string.IsNullOrEmpty(savedRedirectBrowser))
        {
            // Find matching browser in combo
            for (int i = 0; i < _installedBrowsers.Count; i++)
            {
                if (_installedBrowsers[i].Path.Equals(savedRedirectBrowser, StringComparison.OrdinalIgnoreCase))
                {
                    _redirectBrowserCombo.SelectedIndex = i + 1; // +1 because "Auto-detect" is at index 0
                    break;
                }
            }
        }
    }

    private void UpdateRegistrationStatus()
    {
        if (_registryManager.IsBrowserRegistered())
        {
            _registrationStatusLabel.Text = "Registration: ✅ Registered as browser capability";
            _registrationStatusLabel.ForeColor = Color.FromArgb(100, 200, 100);
            _unregisterBtn.Enabled = true;
        }
        else
        {
            _registrationStatusLabel.Text = "Registration: ❌ Not registered";
            _registrationStatusLabel.ForeColor = Color.Gray;
            _unregisterBtn.Enabled = false;
        }
    }

    private void OnSetDefaultBrowserClick(object? sender, EventArgs e)
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exePath))
            {
                _registryManager.RegisterAsBrowser(exePath);
                UpdateRegistrationStatus();
                
                // Open Windows Default Apps settings directly to browser selection
                OpenDefaultBrowserSettings();
                
                MessageBox.Show(
                    "LinkShield has been registered as a browser.\n\n" +
                    "The Windows Default Apps settings has been opened.\n" +
                    "Please select 'LinkShield' from the browser list.",
                    "Set Default Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to register as browser: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void OpenDefaultBrowserSettings()
    {
        try
        {
            // Opens Windows Settings directly to Default Apps > Web browser
            Process.Start(new ProcessStartInfo
            {
                FileName = "ms-settings:defaultapps",
                UseShellExecute = true
            });
        }
        catch
        {
            // Fallback to general settings
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "control.exe",
                    Arguments = "/name Microsoft.DefaultPrograms /page pageDefaultProgram",
                    UseShellExecute = true
                });
            }
            catch { }
        }
    }

    private void OnRestoreDefaultBrowserClick(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "This will open Windows Settings where you can select your preferred browser.\n\n" +
            "Do you want to continue?",
            "Restore Browser",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);
        
        if (result == DialogResult.Yes)
        {
            OpenDefaultBrowserSettings();
        }
    }

    private void OnUnregisterClick(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "This will remove LinkShield's browser registration from Windows.\n\n" +
            "⚠️ This will:\n" +
            "• Remove LinkShield from the browser list in Windows Settings\n" +
            "• Remove all URL handler registrations\n" +
            "• Remove auto-start entry (if enabled)\n\n" +
            "You will need to re-register if you want to use LinkShield again.\n\n" +
            "Continue?",
            "Unregister LinkShield",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        
        if (result == DialogResult.Yes)
        {
            try
            {
                _registryManager.CompleteUninstall();
                _autoStartCheckBox.Checked = false;
                UpdateRegistrationStatus();
                
                MessageBox.Show(
                    "LinkShield has been unregistered successfully.\n\n" +
                    "All registry entries have been removed.\n" +
                    "You may need to restart your system for all changes to take effect.",
                    "Unregistration Complete",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to unregister: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void OnRedirectBrowserChanged(object? sender, EventArgs e)
    {
        try
        {
            if (_redirectBrowserCombo.SelectedIndex == 0)
            {
                // Auto-detect - clear saved preference
                _registryManager.SetRedirectBrowserPath(null);
            }
            else
            {
                var selectedBrowser = _installedBrowsers[_redirectBrowserCombo.SelectedIndex - 1];
                _registryManager.SetRedirectBrowserPath(selectedBrowser.Path);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save browser preference: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private bool IsAutoStartEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false);
            return key?.GetValue("LinkShield") != null;
        }
        catch
        {
            return false;
        }
    }

    private void OnAutoStartChanged(object? sender, EventArgs e)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
            
            if (key == null) return;

            if (_autoStartCheckBox.Checked)
            {
                var exePath = Environment.ProcessPath;
                if (!string.IsNullOrEmpty(exePath))
                {
                    key.SetValue("LinkShield", $"\"{exePath}\"");
                }
            }
            else
            {
                key.DeleteValue("LinkShield", false);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to update auto-start setting: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private record BrowserInfo(string Name, string Path);
}
