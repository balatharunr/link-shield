using System.Drawing;
using System.Windows.Forms;
using Microsoft.Extensions.Hosting;

namespace LinkShield.Service;

/// <summary>
/// Manages the system tray icon for LinkShield daemon mode.
/// Provides a visible indicator and context menu for the background service.
/// </summary>
public class TrayIconManager : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly IHostApplicationLifetime _appLifetime;
    private bool _disposed;

    public TrayIconManager(IHostApplicationLifetime appLifetime)
    {
        _appLifetime = appLifetime;
        
        _notifyIcon = new NotifyIcon
        {
            Text = "LinkShield - URL Protection Active",
            Visible = true,
            ContextMenuStrip = CreateContextMenu()
        };

        // Load icon from file or embedded resource
        var iconPath = Path.Combine(AppContext.BaseDirectory, "app.ico");
        if (File.Exists(iconPath))
        {
            _notifyIcon.Icon = new Icon(iconPath);
        }
        else
        {
            // Fallback to system shield icon
            _notifyIcon.Icon = SystemIcons.Shield;
        }

        _notifyIcon.DoubleClick += OnDoubleClick;
    }

    private ContextMenuStrip CreateContextMenu()
    {
        var menu = new ContextMenuStrip();
        
        var statusItem = new ToolStripMenuItem("LinkShield - Active")
        {
            Enabled = false,
            Image = SystemIcons.Shield.ToBitmap()
        };
        menu.Items.Add(statusItem);
        
        menu.Items.Add(new ToolStripSeparator());
        
        var exitItem = new ToolStripMenuItem("Exit LinkShield", null, OnExitClick);
        menu.Items.Add(exitItem);

        return menu;
    }

    private void OnDoubleClick(object? sender, EventArgs e)
    {
        MessageBox.Show(
            "LinkShield is running and protecting your URLs.\n\nRight-click the tray icon to exit.",
            "LinkShield Status",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private void OnExitClick(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "Are you sure you want to exit LinkShield?\n\nURL protection will be disabled.",
            "Exit LinkShield",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result == DialogResult.Yes)
        {
            _notifyIcon.Visible = false;
            _appLifetime.StopApplication();
        }
    }

    public void ShowBalloon(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
    {
        _notifyIcon.ShowBalloonTip(3000, title, message, icon);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
    }
}
