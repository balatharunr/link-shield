using LinkShield.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Drawing;
using System.Reflection;

namespace LinkShield.App;

public partial class MainForm : Form
{
    private readonly IServiceProvider _services;
    private readonly DetectionHistoryService _historyService;
    private readonly NotifyIcon _trayIcon;
    private readonly System.Windows.Forms.Timer _refreshTimer;
    
    // UI Components
    private Panel _headerPanel = null!;
    private Panel _statsPanel = null!;
    private Panel _historyPanel = null!;
    private ListView _historyList = null!;
    private Label _statusLabel = null!;
    private Label _todayStatsLabel = null!;
    private Label _weekStatsLabel = null!;
    private Label _totalStatsLabel = null!;
    private Button _clearHistoryBtn = null!;
    private Button _settingsBtn = null!;
    private Label _protectionStatusLabel = null!;

    public MainForm(IServiceProvider services)
    {
        _services = services;
        _historyService = services.GetRequiredService<DetectionHistoryService>();
        
        InitializeComponent();
        
        _trayIcon = CreateTrayIcon();
        _refreshTimer = new System.Windows.Forms.Timer { Interval = 5000 };
        _refreshTimer.Tick += (s, e) => RefreshData();
        _refreshTimer.Start();
        
        RefreshData();
    }

    private void InitializeComponent()
    {
        // Form settings
        Text = "LinkShield";
        Size = new Size(800, 600);
        MinimumSize = new Size(600, 400);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(18, 18, 18);
        ForeColor = Color.White;
        
        // Load icon
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            var iconPath = Path.Combine(AppContext.BaseDirectory, "Resources", "app.ico");
            if (File.Exists(iconPath))
            {
                Icon = new Icon(iconPath);
            }
            else
            {
                Icon = SystemIcons.Shield;
            }
        }
        catch
        {
            Icon = SystemIcons.Shield;
        }

        // Header Panel
        _headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 70,
            BackColor = Color.FromArgb(28, 28, 28),
            Padding = new Padding(20, 10, 20, 10)
        };

        var titleLabel = new Label
        {
            Text = "🛡️ LinkShield",
            Font = new Font("Segoe UI", 18, FontStyle.Bold),
            ForeColor = Color.FromArgb(0, 200, 83),
            AutoSize = true,
            Location = new Point(20, 12)
        };

        _protectionStatusLabel = new Label
        {
            Text = "● Protection Active",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.FromArgb(0, 200, 83),
            AutoSize = true,
            Location = new Point(20, 45)  // Below the title to avoid overlap
        };

        _settingsBtn = new Button
        {
            Text = "⚙",
            Font = new Font("Segoe UI", 14),
            Size = new Size(40, 40),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent,
            ForeColor = Color.White,
            Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        _settingsBtn.FlatAppearance.BorderSize = 0;
        _settingsBtn.Click += OnSettingsClick;

        _headerPanel.Controls.AddRange(new Control[] { titleLabel, _protectionStatusLabel, _settingsBtn });
        _headerPanel.Resize += (s, e) =>
        {
            _settingsBtn.Location = new Point(_headerPanel.Width - 60, 15);
        };

        // Stats Panel
        _statsPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 120,
            BackColor = Color.FromArgb(18, 18, 18),
            Padding = new Padding(20, 10, 20, 10)
        };

        _todayStatsLabel = CreateStatCard("Today", "0 scanned • 0 blocked", 0);
        _weekStatsLabel = CreateStatCard("This Week", "0 scanned • 0 blocked", 1);
        _totalStatsLabel = CreateStatCard("All Time", "0 scanned • 0 blocked", 2);

        _statsPanel.Controls.AddRange(new Control[] { _todayStatsLabel, _weekStatsLabel, _totalStatsLabel });
        _statsPanel.Resize += (s, e) => LayoutStatCards();

        // History Panel
        _historyPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(18, 18, 18),
            Padding = new Padding(20, 10, 20, 20)
        };

        var historyHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 40,
            BackColor = Color.Transparent
        };

        var historyTitle = new Label
        {
            Text = "Recent Activity",
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            ForeColor = Color.White,
            AutoSize = true,
            Location = new Point(0, 8)
        };

        _clearHistoryBtn = new Button
        {
            Text = "Clear History",
            Font = new Font("Segoe UI", 9),
            Size = new Size(100, 30),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(50, 50, 50),
            ForeColor = Color.White,
            Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        _clearHistoryBtn.FlatAppearance.BorderColor = Color.FromArgb(70, 70, 70);
        _clearHistoryBtn.Click += OnClearHistoryClick;

        historyHeader.Controls.AddRange(new Control[] { historyTitle, _clearHistoryBtn });
        historyHeader.Resize += (s, e) =>
        {
            _clearHistoryBtn.Location = new Point(historyHeader.Width - 120, 5);
        };

        _historyList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            BackColor = Color.FromArgb(28, 28, 28),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.None,
            Font = new Font("Segoe UI", 9),
            HeaderStyle = ColumnHeaderStyle.Nonclickable
        };
        _historyList.Columns.Add("Status", 70);
        _historyList.Columns.Add("URL", 350);
        _historyList.Columns.Add("Time", 150);
        _historyList.OwnerDraw = true;
        _historyList.DrawColumnHeader += HistoryList_DrawColumnHeader;
        _historyList.DrawItem += HistoryList_DrawItem;
        _historyList.DrawSubItem += HistoryList_DrawSubItem;

        _historyPanel.Controls.Add(_historyList);
        _historyPanel.Controls.Add(historyHeader);

        // Add panels to form
        Controls.Add(_historyPanel);
        Controls.Add(_statsPanel);
        Controls.Add(_headerPanel);

        // Events
        FormClosing += OnFormClosing;
        Resize += OnFormResize;
    }

    private Label CreateStatCard(string title, string value, int index)
    {
        var card = new Label
        {
            Text = $"{title}\n{value}",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            BackColor = Color.FromArgb(28, 28, 28),
            TextAlign = ContentAlignment.MiddleCenter,
            Size = new Size(200, 80),
            Tag = index
        };
        return card;
    }

    private void LayoutStatCards()
    {
        var cardWidth = (_statsPanel.Width - 80) / 3;
        var x = 20;
        foreach (Control ctrl in _statsPanel.Controls)
        {
            if (ctrl is Label label && label.Tag is int)
            {
                label.Size = new Size(cardWidth, 80);
                label.Location = new Point(x, 20);
                x += cardWidth + 20;
            }
        }
    }

    private NotifyIcon CreateTrayIcon()
    {
        var trayIcon = new NotifyIcon
        {
            Text = "LinkShield - URL Protection Active",
            Visible = true
        };

        try
        {
            var iconPath = Path.Combine(AppContext.BaseDirectory, "Resources", "app.ico");
            trayIcon.Icon = File.Exists(iconPath) ? new Icon(iconPath) : SystemIcons.Shield;
        }
        catch
        {
            trayIcon.Icon = SystemIcons.Shield;
        }

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open LinkShield", null, (s, e) => ShowWindow());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (s, e) => ExitApplication());
        
        trayIcon.ContextMenuStrip = menu;
        trayIcon.DoubleClick += (s, e) => ShowWindow();

        return trayIcon;
    }

    private void RefreshData()
    {
        if (InvokeRequired)
        {
            Invoke(RefreshData);
            return;
        }

        var analytics = _historyService.GetAnalytics();
        
        _todayStatsLabel.Text = $"Today\n{analytics.TodayScanned} scanned • {analytics.TodayBlocked} blocked";
        _weekStatsLabel.Text = $"This Week\n{analytics.WeekScanned} scanned • {analytics.WeekBlocked} blocked";
        _totalStatsLabel.Text = $"All Time\n{analytics.TotalScanned} scanned • {analytics.TotalBlocked} blocked";

        // Update history list
        _historyList.BeginUpdate();
        _historyList.Items.Clear();
        
        foreach (var record in _historyService.GetRecentDetections(100))
        {
            // Determine status text and color based on detection status
            var (statusText, statusColor) = record.Status switch
            {
                DetectionStatus.Blocked => ("🚫 Blocked", Color.FromArgb(255, 100, 100)),    // Red
                DetectionStatus.DeadLink => ("⚠️ Dead Link", Color.FromArgb(255, 200, 50)),  // Yellow/Orange
                _ => ("✅ Safe", Color.FromArgb(100, 255, 100))                               // Green
            };
            
            var item = new ListViewItem(statusText);
            item.SubItems.Add(TruncateUrl(record.Url, 60));
            item.SubItems.Add(record.DetectedAt.ToLocalTime().ToString("MMM dd, HH:mm:ss"));
            item.Tag = record;
            item.ForeColor = statusColor;
            _historyList.Items.Add(item);
        }
        
        _historyList.EndUpdate();
    }

    private static string TruncateUrl(string url, int maxLength)
    {
        return url.Length <= maxLength ? url : url[..(maxLength - 3)] + "...";
    }

    private void HistoryList_DrawColumnHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        // Fill entire header row with dark grey to eliminate white column issue
        using var brush = new SolidBrush(Color.FromArgb(40, 40, 40));
        
        // For the last column, extend the fill to cover any remaining space
        var fillBounds = e.Bounds;
        if (e.ColumnIndex == _historyList.Columns.Count - 1)
        {
            fillBounds = new Rectangle(e.Bounds.X, e.Bounds.Y, 
                _historyList.ClientSize.Width - e.Bounds.X, e.Bounds.Height);
        }
        
        e.Graphics.FillRectangle(brush, fillBounds);
        e.Graphics.DrawString(e.Header?.Text, _historyList.Font, Brushes.White, e.Bounds.X + 5, e.Bounds.Y + 5);
    }

    private void HistoryList_DrawItem(object? sender, DrawListViewItemEventArgs e)
    {
        e.DrawDefault = true;
    }

    private void HistoryList_DrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        e.DrawDefault = true;
    }

    private void ShowWindow()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }

    private void ExitApplication()
    {
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _refreshTimer.Stop();
        _refreshTimer.Dispose();
        Application.Exit();
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            _trayIcon.ShowBalloonTip(2000, "LinkShield", "Running in background. Right-click tray icon to exit.", ToolTipIcon.Info);
        }
        else
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
    }

    private void OnFormResize(object? sender, EventArgs e)
    {
        LayoutStatCards();
    }

    private void OnSettingsClick(object? sender, EventArgs e)
    {
        using var settingsForm = new SettingsForm(_services);
        settingsForm.ShowDialog(this);
    }

    private void OnClearHistoryClick(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "Are you sure you want to clear all detection history?",
            "Clear History",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);
        
        if (result == DialogResult.Yes)
        {
            _historyService.ClearHistory();
            RefreshData();
        }
    }
}
