# LinkShield

**LinkShield** is a real-time phishing protection system for Windows that operates as a "split-personality" security tool: a URL interceptor and a background daemon service. It protects users by intercepting suspicious links before they reach the browser and blocking known malicious domains via DNS sinkholing.

## 🎯 What is LinkShield?

LinkShield provides multi-layered protection against phishing and malware threats:

- **URL Interception**: Registers as a Windows browser to intercept links clicked in desktop applications (WhatsApp, Slack, Outlook, etc.) and analyzes them in real-time before forwarding to your actual browser.
- **DNS Sinkhole**: Acts as a local DNS server that blocks malicious domains by resolving them to `0.0.0.0`, preventing connections before they happen.
- **Automatic Threat Intelligence**: Downloads and syncs daily threat feeds from OpenPhish, maintaining a local SQLite database of known malicious domains.
- **Fast Performance**: Sub-20ms URL analysis using optimized SQLite queries with WAL mode for concurrent reads during background updates.

## 🏗️ Architecture

### Dual-Mode Operation

**Interceptor Mode** (Fast-Path):
```
Desktop App Click → LinkShield → Threat Check → Safe? → Real Browser
                                                  ↓ Blocked? → Toast Notification
```

**Daemon Mode** (Background Service):
```
┌─ ThreatFeedSyncWorker: Downloads OpenPhish feed every 24 hours
│  └─ Updates SQLite database with new malicious domains
│
└─ DnsSinkholeWorker: Local DNS server (127.0.0.1:53)
   └─ Forwards safe queries to 8.8.8.8, sinkholes malicious domains to 0.0.0.0
```

### Technology Stack

- **.NET 8**: Cross-platform framework with Worker Service support
- **SQLite with EF Core**: Fast local threat database with WAL mode for concurrent access
- **Windows Registry Integration**: Browser capability registration
- **HTTP Client**: OpenPhish threat feed synchronization
- **PowerShell Integration**: Windows Toast notifications and DNS configuration

## 📋 Prerequisites

- **Operating System**: Windows 10/11
- **.NET 8 SDK**: [Download here](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Administrator Privileges**: Required for DNS configuration and registry writes

## 🚀 How to Run

### Step 1: Build the Project

```powershell
# Navigate to project directory
cd Y:\Cyber

# Build the solution
dotnet build LinkShield.slnx

# (Optional) Publish for deployment
dotnet publish LinkShield.Service -c Release -o .\publish
```

### Step 2: Run in Daemon Mode

**Important**: Run as Administrator for full functionality (DNS sinkhole requires port 53 access).

```powershell
# From source (development)
cd LinkShield.Service
dotnet run

# From published build
.\publish\LinkShield.Service.exe
```

**Expected Output:**
```
info: LinkShield.Core.WindowsRegistryManager[0]
      Registering LinkShield as browser capability...
info: LinkShield.Core.ThreatDatabaseService[0]
      Threat database initialized at C:\Users\...\AppData\Local\LinkShield\threats.db
info: LinkShield.Service.ThreatFeedSyncWorker[0]
      Threat feed sync complete. Inserted: 234, Total in DB: 474.
info: LinkShield.Service.DnsSinkholeWorker[0]
      DNS Sinkhole listening on 127.0.0.1:53
info: Microsoft.Hosting.Lifetime[0]
      Application started. Press Ctrl+C to shut down.
```

### Step 3: Test Interceptor Mode (Manual)

Test URL interception directly by passing a URL as an argument:

```powershell
# Test with a safe URL (should open in your real browser)
.\publish\LinkShield.Service.exe "https://www.google.com"

# Test with a known malicious URL (should be blocked with toast notification)
.\publish\LinkShield.Service.exe "https://malware.wicar.org/test"
```

## 🌐 Setting Up as Default Browser

To enable automatic link interception from desktop applications (WhatsApp, Slack, email clients, etc.):

### Step 1: Register LinkShield

Run LinkShield at least once in daemon mode. It will automatically register itself as a browser capability in the Windows Registry.

### Step 2: Set as Default Browser

1. Open **Windows Settings**
2. Navigate to **Apps** → **Default apps**
3. Click on **Web browser** (shows your current default browser)
4. Select **LinkShield** from the list of available browsers
5. Close Settings

![Default Browser Setup](https://i.imgur.com/placeholder.png)

> **Note**: If LinkShield doesn't appear in the list, close and reopen Windows Settings after running the application once.

### Step 3: Verify It Works

Send yourself a test link in WhatsApp Desktop or any other application:

- **Safe Link** (e.g., `https://www.google.com`): Opens in your original browser
- **Malicious Link** (e.g., `https://malware.wicar.org/`): Blocked with toast notification

### How It Works

When you click a link:
1. Windows routes the URL to LinkShield (registered as default browser)
2. LinkShield analyzes the URL against:
   - Bootstrap blocklist (from `appsettings.json`)
   - SQLite threat database (OpenPhish feed)
3. **If malicious**: Shows toast notification, blocks URL
4. **If safe**: Launches your **real browser** (Chrome/Edge/Firefox) with the URL

LinkShield reads your previous default browser from the registry backup and uses that to forward safe URLs, preventing infinite loops.

## ⚙️ Configuration

Edit `LinkShield.Service/appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information"
    }
  },
  "BootstrapBlocklist": [
    "malware.wicar.org",
    "testsafebrowsing.appspot.com",
    "itisatrap.org",
    "amtso.org",
    "phishing.testcategory.com"
  ],
  "UpstreamDns": "8.8.8.8"
}
```

### Configuration Options

- **BootstrapBlocklist**: List of domains to block immediately without database lookup (useful for testing and critical threats)
- **UpstreamDns**: DNS server to forward legitimate queries to (default: Google DNS 8.8.8.8)

## 🗂️ Project Structure

```
LinkShield/
├── LinkShield.Core/              # Core business logic
│   ├── IUrlAnalyzer.cs          # URL analysis interface
│   ├── SqliteUrlAnalyzer.cs     # Main threat detection logic
│   ├── ThreatDatabaseService.cs # SQLite database management
│   ├── ThreatDbContext.cs       # EF Core DbContext
│   ├── MaliciousDomain.cs       # Domain entity model
│   └── WindowsRegistryManager.cs # Browser registration logic
│
├── LinkShield.Service/           # Background service & entry point
│   ├── Program.cs               # Split-personality entry point
│   ├── ThreatFeedSyncWorker.cs  # OpenPhish feed downloader
│   ├── DnsSinkholeWorker.cs     # DNS server implementation
│   └── appsettings.json         # Configuration
│
└── LinkShield.slnx              # Solution file
```

## 🗄️ Data Storage

LinkShield stores its threat database in:
```
%LOCALAPPDATA%\LinkShield\threats.db
```

The database uses SQLite with WAL (Write-Ahead Logging) mode for:
- Fast concurrent reads during URL analysis
- Non-blocking writes during background sync
- Crash recovery

## 🛡️ Security Features

### 1. Bootstrap Blocklist
Hardcoded high-priority threats in config file for instant blocking without database dependency.

### 2. Threat Intelligence Sync
Automatic daily updates from OpenPhish feed containing thousands of verified phishing URLs.

### 3. DNS Sinkhole
Blocks malicious domains at the DNS level before any connection is established.

### 4. Fail-Open Design
If analysis fails due to an error, URLs are forwarded to the real browser rather than blocking legitimate traffic.

### 5. Windows Toast Notifications
Visual alerts when threats are blocked, keeping users informed.

## 🧪 Testing

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for comprehensive testing instructions including:
- URI interceptor testing
- DNS sinkhole verification
- WAL mode validation
- Crash recovery testing

Quick test commands:
```powershell
# Test safe URL
.\LinkShield.Service.exe "https://www.google.com"

# Test blocked URL
.\LinkShield.Service.exe "https://malware.wicar.org/"

# Check DNS resolution
nslookup malware.wicar.org 127.0.0.1
# Should return: 0.0.0.0
```

## 🔄 Reverting to Normal Browser

### Option 1: Windows Settings (Recommended)
1. Open **Windows Settings** → **Apps** → **Default apps**
2. Click **Web browser**
3. Select your original browser (Chrome, Edge, Firefox, etc.)

### Option 2: DNS Reset (If DNS is stuck)
```powershell
# Emergency DNS reset
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
# Replace "Wi-Fi" with your network adapter name
```

### Option 3: Full Cleanup (Remove all traces)
```powershell
# Stop LinkShield if running (Ctrl+C)

# Clean registry entries
reg delete "HKCU\Software\Classes\LinkShieldURL" /f
reg delete "HKCU\Software\Clients\StartMenuInternet\LinkShield" /f
reg delete "HKCU\Software\RegisteredApplications" /v LinkShield /f
reg delete "HKCU\Software\LinkShield" /f

# Delete threat database
Remove-Item "$env:LOCALAPPDATA\LinkShield\threats.db*"
```

## 📊 Performance

- **URL Analysis**: <20ms (in-memory cache + indexed SQLite queries)
- **DNS Query**: <10ms (local lookup with upstream forwarding)
- **Database Size**: ~100KB for 1000 domains
- **Memory Usage**: ~50MB baseline (daemon mode)

## 🚨 Known Limitations

- **Windows Only**: Registry and DNS integration are Windows-specific
- **Administrator Required**: DNS sinkhole needs port 53 binding privileges
- **Single Network Adapter**: DNS configuration targets primary adapter (usually "Wi-Fi" or "Ethernet")
- **No HTTPS Inspection**: Cannot decrypt TLS traffic (by design - respects privacy)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is provided as-is for educational and security research purposes.

## 🙏 Acknowledgments

- **OpenPhish**: Community threat intelligence feed
- **.NET Team**: Excellent Worker Service framework
- **SQLite**: Fast, reliable embedded database

## ⚠️ Disclaimer

LinkShield is a security tool intended for personal protection and educational purposes. Use responsibly and ensure compliance with your organization's security policies. The authors are not responsible for any misuse or damage caused by this software.

---

**Made with ❤️ for a safer internet**
