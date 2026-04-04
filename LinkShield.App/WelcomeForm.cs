using LinkShield.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using System.Drawing;

namespace LinkShield.App;

public partial class WelcomeForm : Form
{
    private readonly IServiceProvider _services;
    private readonly WindowsRegistryManager _registryManager;
    private int _currentStep = 0;
    private Panel _contentPanel = null!;
    private Button _nextBtn = null!;
    private Button _skipBtn = null!;
    private Label _stepIndicator = null!;

    public WelcomeForm(IServiceProvider services)
    {
        _services = services;
        _registryManager = services.GetRequiredService<WindowsRegistryManager>();
        InitializeComponent();
        ShowStep(0);
    }

    private void InitializeComponent()
    {
        Text = "Welcome to LinkShield";
        Size = new Size(600, 500);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Color.FromArgb(18, 18, 18);
        ForeColor = Color.White;

        // Header
        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 80,
            BackColor = Color.FromArgb(28, 28, 28)
        };

        var titleLabel = new Label
        {
            Text = "🛡️ Welcome to LinkShield",
            Font = new Font("Segoe UI", 20, FontStyle.Bold),
            ForeColor = Color.FromArgb(0, 200, 83),
            AutoSize = true,
            Location = new Point(30, 25)
        };
        headerPanel.Controls.Add(titleLabel);

        // Content Panel - with scrolling support
        _contentPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(18, 18, 18),
            Padding = new Padding(30),
            AutoScroll = true
        };

        // Footer with navigation
        var footerPanel = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 70,
            BackColor = Color.FromArgb(28, 28, 28)
        };

        _stepIndicator = new Label
        {
            Text = "Step 1 of 3",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Gray,
            Location = new Point(30, 25),
            AutoSize = true
        };

        _skipBtn = new Button
        {
            Text = "Skip Setup",
            Font = new Font("Segoe UI", 9),
            Size = new Size(100, 35),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(50, 50, 50),
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        _skipBtn.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 80);
        _skipBtn.Click += (s, e) => Close();

        _nextBtn = new Button
        {
            Text = "Next →",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            Size = new Size(120, 40),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(0, 120, 215),
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        _nextBtn.FlatAppearance.BorderSize = 0;
        _nextBtn.Click += OnNextClick;

        footerPanel.Controls.AddRange(new Control[] { _stepIndicator, _skipBtn, _nextBtn });
        footerPanel.Resize += (s, e) =>
        {
            _skipBtn.Location = new Point(footerPanel.Width - 250, 18);
            _nextBtn.Location = new Point(footerPanel.Width - 140, 15);
        };

        Controls.Add(_contentPanel);
        Controls.Add(footerPanel);
        Controls.Add(headerPanel);
    }

    private void ShowStep(int step)
    {
        _currentStep = step;
        _contentPanel.Controls.Clear();

        switch (step)
        {
            case 0:
                ShowIntroStep();
                break;
            case 1:
                ShowSetDefaultBrowserStep();
                break;
            case 2:
                ShowFinalStep();
                break;
        }

        _stepIndicator.Text = $"Step {step + 1} of 3";
        _nextBtn.Text = step == 2 ? "Get Started!" : "Next →";
        _skipBtn.Visible = step < 2;
    }

    private void ShowIntroStep()
    {
        var content = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4
        };
        content.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        content.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        content.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var introText = new Label
        {
            Text = "LinkShield protects you from malicious URLs by analyzing every link\nbefore opening it in your browser.",
            Font = new Font("Segoe UI", 11),
            ForeColor = Color.White,
            AutoSize = true,
            Padding = new Padding(0, 10, 0, 20)
        };

        var featuresPanel = CreateFeaturesList();

        content.Controls.Add(introText, 0, 0);
        content.Controls.Add(featuresPanel, 0, 1);

        _contentPanel.Controls.Add(content);
    }

    private Panel CreateFeaturesList()
    {
        var panel = new Panel
        {
            AutoSize = true,
            Padding = new Padding(0, 10, 0, 10)
        };

        var features = new[]
        {
            ("🔍", "Real-time URL Analysis", "Checks every link against known threat databases"),
            ("🤖", "ML-Powered Detection", "Uses machine learning to detect zero-day phishing"),
            ("⚠️", "Dead Link Detection", "Warns you about non-existent domains"),
            ("🔒", "Brand Impersonation Detection", "Identifies fake login pages"),
            ("📊", "Activity Dashboard", "Track all scanned and blocked URLs")
        };

        int y = 0;
        foreach (var (icon, title, desc) in features)
        {
            var iconLabel = new Label
            {
                Text = icon,
                Font = new Font("Segoe UI", 16),
                Location = new Point(0, y),
                Size = new Size(40, 35)
            };

            var titleLabel = new Label
            {
                Text = title,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(45, y),
                AutoSize = true
            };

            var descLabel = new Label
            {
                Text = desc,
                Font = new Font("Segoe UI", 9),
                ForeColor = Color.Gray,
                Location = new Point(45, y + 20),
                AutoSize = true
            };

            panel.Controls.AddRange(new Control[] { iconLabel, titleLabel, descLabel });
            y += 50;
        }

        panel.Height = y;
        return panel;
    }

    private void ShowSetDefaultBrowserStep()
    {
        var content = new Panel
        {
            Dock = DockStyle.Fill
        };

        var titleLabel = new Label
        {
            Text = "Set LinkShield as Default Browser",
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(0, 10),
            AutoSize = true
        };

        var descLabel = new Label
        {
            Text = "For LinkShield to protect you, it needs to intercept URLs before they\nopen. This requires setting it as your default browser handler.\n\nDon't worry - safe URLs will still open in your preferred browser!",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.LightGray,
            Location = new Point(0, 50),
            AutoSize = true
        };

        var stepsPanel = new Panel
        {
            Location = new Point(0, 140),
            Size = new Size(520, 180),
            BackColor = Color.FromArgb(28, 28, 28)
        };

        var stepsTitle = new Label
        {
            Text = "📋 Steps to complete setup:",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(15, 15),
            AutoSize = true
        };

        var steps = new[]
        {
            "1. Click the button below to register LinkShield",
            "2. Windows Settings will open to the Default Apps page",
            "3. Click 'Web browser' and select 'LinkShield' from the list",
            "4. Close Windows Settings and return here"
        };

        int y = 45;
        foreach (var step in steps)
        {
            var stepLabel = new Label
            {
                Text = step,
                Font = new Font("Segoe UI", 9),
                ForeColor = Color.LightGray,
                Location = new Point(15, y),
                AutoSize = true
            };
            stepsPanel.Controls.Add(stepLabel);
            y += 25;
        }

        stepsPanel.Controls.Add(stepsTitle);

        var setDefaultBtn = new Button
        {
            Text = "🔧 Register & Open Settings",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            Size = new Size(250, 45),
            Location = new Point(0, 330),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(0, 120, 215),
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        setDefaultBtn.FlatAppearance.BorderSize = 0;
        setDefaultBtn.Click += OnSetDefaultBrowserClick;

        content.Controls.AddRange(new Control[] { titleLabel, descLabel, stepsPanel, setDefaultBtn });
        _contentPanel.Controls.Add(content);
    }

    private void OnSetDefaultBrowserClick(object? sender, EventArgs e)
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exePath))
            {
                _registryManager.RegisterAsBrowser(exePath);

                // Open Windows Default Apps settings
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:defaultapps",
                    UseShellExecute = true
                });

                MessageBox.Show(
                    "LinkShield has been registered!\n\n" +
                    "Please select 'LinkShield' from the Web browser list\nin the Windows Settings window that just opened.",
                    "Setup",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to register: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ShowFinalStep()
    {
        var content = new Panel
        {
            Dock = DockStyle.Fill
        };

        var titleLabel = new Label
        {
            Text = "✅ You're All Set!",
            Font = new Font("Segoe UI", 16, FontStyle.Bold),
            ForeColor = Color.FromArgb(0, 200, 83),
            Location = new Point(0, 10),
            AutoSize = true
        };

        var descLabel = new Label
        {
            Text = "LinkShield is now ready to protect you from malicious URLs.\n\nHere's what happens when you click a link:",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.LightGray,
            Location = new Point(0, 50),
            AutoSize = true
        };

        var flowPanel = new Panel
        {
            Location = new Point(0, 120),
            Size = new Size(520, 200),
            BackColor = Color.FromArgb(28, 28, 28)
        };

        var flowSteps = new[]
        {
            ("1️⃣", "Link Intercepted", "LinkShield catches the URL before your browser"),
            ("2️⃣", "Analysis Runs", "Checks threat databases, ML model, and brand detection"),
            ("3️⃣", "Decision Made", "Safe links open normally, threats are blocked"),
            ("4️⃣", "You're Protected", "View all activity in the LinkShield dashboard")
        };

        int y = 15;
        foreach (var (icon, title, desc) in flowSteps)
        {
            var iconLabel = new Label
            {
                Text = icon,
                Font = new Font("Segoe UI", 12),
                Location = new Point(15, y),
                AutoSize = true
            };

            var titleLabel2 = new Label
            {
                Text = title,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(50, y),
                AutoSize = true
            };

            var descLabel2 = new Label
            {
                Text = desc,
                Font = new Font("Segoe UI", 9),
                ForeColor = Color.Gray,
                Location = new Point(50, y + 18),
                AutoSize = true
            };

            flowPanel.Controls.AddRange(new Control[] { iconLabel, titleLabel2, descLabel2 });
            y += 45;
        }

        var tipLabel = new Label
        {
            Text = "💡 Tip: LinkShield runs in the background. Look for the shield icon\n     in your system tray to access settings or view activity.",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Gray,
            Location = new Point(0, 340),
            AutoSize = true
        };

        content.Controls.AddRange(new Control[] { titleLabel, descLabel, flowPanel, tipLabel });
        _contentPanel.Controls.Add(content);
    }

    private void OnNextClick(object? sender, EventArgs e)
    {
        if (_currentStep < 2)
        {
            ShowStep(_currentStep + 1);
        }
        else
        {
            // Mark setup as complete
            MarkSetupComplete();
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private void MarkSetupComplete()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(
                @"SOFTWARE\LinkShield");
            key?.SetValue("SetupCompleted", "1");
        }
        catch { }
    }

    public static bool ShouldShowWelcome()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\LinkShield", false);
            var value = key?.GetValue("SetupCompleted");
            return value == null || value.ToString() != "1";
        }
        catch
        {
            return true;
        }
    }
}
