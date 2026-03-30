# LinkShield Testing Guide

## Prerequisites
- Windows 10/11
- .NET 8 SDK
- **Run terminal as Administrator** (required for DNS port 53 and registry writes)

---

## Step 0: Build & Publish
```powershell
cd Y:\Cyber
dotnet build
dotnet publish LinkShield.Service -c Release -o .\publish
```

---

## Phase 1: Test URI Interceptor (WhatsApp / Desktop App Clicks)

### 1.1 Verify Registry Registration
```powershell
# Start daemon mode (registers browser capability)
.\publish\LinkShield.Service.exe

# You should see the "ACTION REQUIRED" message.
# Press Ctrl+C to stop.
```

Verify registry entries were created:
```powershell
reg query "HKCU\Software\Classes\LinkShieldURL\shell\open\command"
# Should show: "Y:\Cyber\publish\LinkShield.Service.exe" "%1"

reg query "HKCU\Software\Clients\StartMenuInternet\LinkShield\Capabilities\URLAssociations"
# Should show: http = LinkShieldURL, https = LinkShieldURL

reg query "HKCU\Software\RegisteredApplications" /v LinkShield
# Should show the capabilities path
```

### 1.2 Set LinkShield as Default Browser
1. Open **Windows Settings > Apps > Default apps**
2. Under **Web browser**, click the current browser
3. Select **LinkShield** from the list
4. If LinkShield doesn't appear, close and reopen Settings

### 1.3 Test Interceptor — SAFE URL
```powershell
# Simulate a desktop app clicking a link:
.\publish\LinkShield.Service.exe "https://www.google.com"
```
**Expected:** Google opens in your REAL browser (Chrome/Edge/Firefox), NOT in LinkShield again.

### 1.4 Test Interceptor — MALICIOUS URL (Bootstrap Blocklist)
```powershell
.\publish\LinkShield.Service.exe "https://malware.wicar.org/test"
```
**Expected:**
- URL is **NOT** opened in any browser
- A Windows Toast notification appears: "LinkShield: Threat Blocked"
- Console shows: `BLOCKED malicious URL`

### 1.5 Test from WhatsApp Desktop
1. Send yourself a link to `https://malware.wicar.org/` in WhatsApp
2. Click it in WhatsApp Desktop
**Expected:** Toast notification, URL blocked.

3. Send yourself `https://www.google.com`
4. Click it in WhatsApp Desktop
**Expected:** Opens in your real browser normally.

### 1.6 Revert Default Browser
When done testing, go to **Settings > Default apps** and switch back to Chrome/Edge.

Or run cleanup:
```powershell
# The daemon's Ctrl+C doesn't unregister. To manually clean up:
reg delete "HKCU\Software\Classes\LinkShieldURL" /f
reg delete "HKCU\Software\Clients\StartMenuInternet\LinkShield" /f
reg delete "HKCU\Software\RegisteredApplications" /v LinkShield /f
```

---

## Phase 2: Test Fast-Cache & WAL

### 2.1 Verify Bootstrap Blocklist from Config
```powershell
# Check appsettings.json has BootstrapBlocklist:
type .\publish\appsettings.json
# Should list: malware.wicar.org, testsafebrowsing.appspot.com, etc.
```

```powershell
# Test a bootstrapped domain:
.\publish\LinkShield.Service.exe "https://testsafebrowsing.appspot.com/"
# Expected: BLOCKED (from bootstrap list, no DB needed)

.\publish\LinkShield.Service.exe "https://itisatrap.org/"
# Expected: BLOCKED
```

### 2.2 Verify WAL Mode
```powershell
# Start daemon to initialize DB:
.\publish\LinkShield.Service.exe
# Wait for "Threat database initialized" log, then Ctrl+C.

# Check WAL mode:
$dbPath = "$env:LOCALAPPDATA\LinkShield\threats.db"
sqlite3 $dbPath "PRAGMA journal_mode;"
# Expected output: wal
```

If you don't have sqlite3 CLI, check that these files exist after the daemon runs:
```powershell
ls "$env:LOCALAPPDATA\LinkShield\"
# Should see: threats.db, threats.db-wal, threats.db-shm
```

### 2.3 Verify Feed Sync
```powershell
# Start daemon and wait for first sync (immediate on start):
.\publish\LinkShield.Service.exe
# Watch for: "Threat feed sync complete. Inserted: X, Total in DB: Y"
# This confirms OpenPhish feed downloaded and domains were stored.
```

---

## Phase 3: Test DNS Sinkhole

> **WARNING:** This test temporarily changes your system DNS to 127.0.0.1.
> If anything goes wrong, manually reset DNS:
> ```powershell
> # Emergency DNS reset:
> Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
> # Replace "Wi-Fi" with your adapter name (run Get-NetAdapter to check)
> ```

### 3.1 Start Daemon Mode (as Administrator)
```powershell
# MUST be admin for port 53:
.\publish\LinkShield.Service.exe
```
**Expected logs:**
```
DNS Sinkhole starting...
DNS redirected to 127.0.0.1 on adapter 'Wi-Fi'
DNS Sinkhole listening on 127.0.0.1:53
```

### 3.2 Verify DNS Was Changed
In a separate admin PowerShell:
```powershell
Get-DnsClientServerAddress -InterfaceAlias "Wi-Fi"
# ServerAddresses should show: 127.0.0.1
```

### 3.3 Test DNS — Safe Domain
```powershell
nslookup google.com 127.0.0.1
# Expected: Returns Google's real IP (forwarded through 8.8.8.8)
```

Open Chrome and browse to `https://www.google.com`:
**Expected:** Page loads normally.

### 3.4 Test DNS — Malicious Domain (Sinkholed)
```powershell
nslookup malware.wicar.org 127.0.0.1
# Expected: Returns 0.0.0.0 (sinkholed!)
```

Open Chrome and browse to `http://malware.wicar.org/`:
**Expected:** Page fails to load (connection refused / DNS resolved to 0.0.0.0).

Check the daemon console for:
```
DNS SINKHOLED: malware.wicar.org -> 0.0.0.0
```

### 3.5 Test DNS Revert — Graceful Stop
Press **Ctrl+C** in the daemon console.
**Expected logs:**
```
DNS Sinkhole stopping — reverting DNS settings...
DNS reverted to DHCP/automatic on 'Wi-Fi'
```

Verify:
```powershell
Get-DnsClientServerAddress -InterfaceAlias "Wi-Fi"
# Should be back to DHCP / your normal DNS
nslookup google.com
# Should resolve normally
```

### 3.6 Test DNS Revert — Crash Recovery (Sentinel File)
```powershell
# Start daemon:
.\publish\LinkShield.Service.exe

# In another terminal, KILL it (simulates crash):
taskkill /F /IM LinkShield.Service.exe

# DNS is now broken (pointing at dead 127.0.0.1).
# Verify sentinel file exists:
type "$env:LOCALAPPDATA\LinkShield\dns_needs_reset"
# Should show your adapter name

# Restart daemon:
.\publish\LinkShield.Service.exe
# Expected: "Detected orphaned DNS override from a previous crash... Reverting..."
# DNS is automatically cleaned up before the new instance takes over.
```

---

## Cleanup Checklist
After all testing:
1. **Ctrl+C** the daemon (reverts DNS automatically)
2. Reset default browser in Windows Settings
3. Optionally clean registry:
   ```powershell
   reg delete "HKCU\Software\Classes\LinkShieldURL" /f
   reg delete "HKCU\Software\Clients\StartMenuInternet\LinkShield" /f
   reg delete "HKCU\Software\RegisteredApplications" /v LinkShield /f
   reg delete "HKCU\Software\LinkShield" /f
   ```
4. Delete threat DB: `del "$env:LOCALAPPDATA\LinkShield\threats.db*"`
