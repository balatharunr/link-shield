# LinkShield

**LinkShield** is a single, unified Windows security application that protects you from phishing and malware by intercepting URLs before they reach your browser. It features a modern UI with detection history, analytics, and easy exit from the system tray.

## ⬇️ Download

Download the latest release from [GitHub Releases](https://github.com/YOUR_USERNAME/LinkShield/releases):
- **LinkShield.exe** (Single file, ~72MB, self-contained - no .NET installation required)

## 🎯 What is LinkShield?

LinkShield provides real-time protection against phishing and malware threats:

- **URL Interception**: Acts as a lightweight "browser" that intercepts links from apps (WhatsApp, Slack, Outlook, etc.), analyzes them, and forwards safe ones to your real browser.
- **Modern Dashboard**: View recent detections, analytics, and protection statistics in a clean, dark-themed interface.
- **System Tray Integration**: Runs quietly in the background with easy access to show/exit from the tray icon.
- **Automatic Threat Intelligence**: Syncs threat feeds from OpenPhish every 6 hours.
- **Windows Toast Notifications**: Get alerted when malicious URLs are blocked.
- **Browser Selection**: Choose which browser receives your safe URLs after scanning.

## 📸 Screenshots

### Main Dashboard
```
┌────────────────────────────────────────────────────────┐
│  🛡️ LinkShield  ● Protection Active              ⚙  │
├────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Today   │  │ This Week   │  │ All Time    │        │
│  │ 24 / 2  │  │ 156 / 12    │  │ 847 / 45    │        │
│  └─────────┘  └─────────────┘  └─────────────┘        │
├────────────────────────────────────────────────────────┤
│  Recent Activity                        [Clear History]│
│  ──────────────────────────────────────────────────── │
│  🚫 Blocked   phishing-site.net/...     Apr 3, 10:15  │
│  ✅ Safe      google.com/search?q=...   Apr 3, 10:14  │
│  ✅ Safe      github.com/user/repo      Apr 3, 10:10  │
│  🚫 Blocked   malware.evil.org/dl       Apr 3, 09:45  │
└────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Download & Run

1. Download `LinkShield.exe` from [Releases](https://github.com/YOUR_USERNAME/LinkShield/releases)
2. Double-click to run (no installation required)
3. LinkShield appears in your system tray with a shield icon

### 2. Set as Default Browser (Required for Link Interception)

1. Right-click tray icon → **Open LinkShield**
2. Click the **⚙ Settings** button
3. Click **Set LinkShield as Default Browser**
4. Windows Settings will automatically open - select **LinkShield** from the browser list

### 3. Choose Your Redirect Browser (Optional)

In Settings, you can select which browser LinkShield should use to open safe URLs:
- **Auto-detect**: Uses your original browser (before setting LinkShield as default)
- Or pick from installed browsers: Chrome, Edge, Firefox, Brave, etc.

### 4. You're Protected!

When you click any link in apps like WhatsApp, Slack, email, etc.:
- **Safe URLs**: Automatically open in your selected browser
- **Malicious URLs**: Blocked with a Windows notification

## 📋 Features

### Dashboard
- **Protection Status**: Shows if LinkShield is actively protecting you
- **Statistics**: URLs scanned and blocked (today, this week, all time)
- **Detection History**: Scrollable list of all URL checks with timestamps
- **Clear History**: Wipe detection history for privacy

### Settings
- **Set Default Browser**: One-click registration + opens Windows Settings automatically
- **Redirect Browser Selection**: Choose which browser receives safe URLs
- **Start with Windows**: Auto-launch on login
- **Notifications**: Toggle threat notifications

### System Tray
- **Show Dashboard**: Double-click tray icon
- **Exit**: Right-click → Exit (completely closes LinkShield)
- **Minimize to Tray**: Closing the window minimizes to tray (not exit)

## 🏗️ How It Works

```
Link Click (WhatsApp, Email, etc.)
         │
         ▼
  ┌─────────────────┐
  │   LinkShield    │ ← Registered as "browser"
  │   Analyzes URL  │
  └────────┬────────┘
           │
    ┌──────┴──────┐
    │             │
    ▼             ▼
  Safe?       Malicious?
    │             │
    ▼             ▼
 Open in       Block &
 Selected      Notify
 Browser
```

### Threat Detection (Waterfall)
```
URL Click → Bootstrap Blocklist → SQLite Database → ML Model → Safe/Block
```

1. **Bootstrap Blocklist**: Instant blocking of known threats (configurable in appsettings.json)
2. **SQLite Database**: Local cache of 10,000s of phishing domains from threat feeds
3. **Multi-Source Threat Feeds**:
   - **OpenPhish**: Community-driven phishing URL feed
   - **PhishTank**: Verified phishing database (operated by Cisco)
4. **🤖 ML Zero-Day Detection** (NEW): Machine learning model catches unknown phishing URLs
   - ONNX-based RandomForest classifier
   - Analyzes URL lexical features (length, entropy, suspicious keywords, etc.)
   - Blocks URLs scoring ≥85% threat probability
   - Catches phishing attempts not yet in any database
5. **Automatic Sync**: Updates threat feeds every 6 hours

## 📁 Data Storage

LinkShield stores data in:
```
%LOCALAPPDATA%\LinkShield\
├── threats.db              # Threat database (SQLite)
└── detection_history.json  # Your detection history
```

Registry settings:
```
HKCU\Software\LinkShield\BackupConfig
├── PreviousBrowserExe    # Your original default browser
└── RedirectBrowserExe    # Your selected redirect browser (optional)
```

## ⚙️ Configuration

Configuration is stored in `appsettings.json` (next to the exe):

```json
{
  "BootstrapBlocklist": [
    "malware.com",
    "phishing-site.net"
  ]
}
```

## 🔄 Restoring Your Original Browser

### Option 1: From LinkShield
1. Open LinkShield → Settings
2. Click **Restore Original Browser**
3. Select your preferred browser in Windows Settings

### Option 2: Windows Settings
1. Go to **Windows Settings** → **Apps** → **Default Apps**
2. Click **Web browser**
3. Select Chrome, Edge, Firefox, etc.

## 🔒 Privacy

- **No cloud sync**: All data stays local on your device
- **No telemetry**: LinkShield doesn't phone home
- **Open source**: Inspect the code yourself

## 🛠️ Building from Source

### Prerequisites
- Windows 10/11
- .NET 8 SDK

### Build Commands

```powershell
# Clone the repository
git clone https://github.com/YOUR_USERNAME/LinkShield.git
cd LinkShield

# Build debug version
dotnet build LinkShield.slnx

# Run the application (development)
dotnet run --project LinkShield.App

# Publish single-file exe
dotnet publish LinkShield.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish
```

### Project Structure

```
LinkShield/
├── LinkShield.Core/        # Core threat detection logic & registry management
├── LinkShield.App/         # WinForms application (⚠️ MAIN ENTRY POINT)
├── LinkShield.Service/     # Legacy background service (see note below)
├── publish/                # Published exe output
└── LinkShield.slnx         # Solution file
```

> ⚠️ **Important: App vs Service**
> 
> - **Always run `LinkShield.App`** - This is the main application with the full GUI, system tray integration, and all features.
> - **`LinkShield.Service`** is a legacy/headless implementation used during development. It provides basic URL interception with a tray icon but no GUI. **Do not use it for production.**
> 
> If you accidentally run the Service, you'll see a simpler tray icon without the main dashboard. The App provides the complete experience.

## 📊 Performance

- **URL Analysis**: <20ms
- **Memory Usage**: ~80MB
- **Exe Size**: ~72MB (self-contained, no dependencies)
- **Startup Time**: <2 seconds

## 🚨 Troubleshooting

### LinkShield doesn't appear in default browser list
1. Run LinkShield once (it auto-registers itself)
2. Close and reopen Windows Settings

### Links still open in old browser
1. Verify LinkShield is running (check system tray)
2. Verify it's set as default browser in Windows Settings

### How to completely exit
Right-click tray icon → **Exit** (closing the window only minimizes)

### Running the wrong project
Make sure to run `LinkShield.App`, not `LinkShield.Service`. The App project is the main entry point with the full GUI.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

## 📄 License

MIT License - Free for personal and commercial use.

## ⚠️ Disclaimer

LinkShield is for personal protection and educational purposes. Use responsibly.

---

**Made with ❤️ for a safer internet**
