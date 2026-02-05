# 🔐 LPU Wireless Auto-Login

A Python automation tool that securely logs you into LPU's 24online wireless network with a single click!

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-Automation-green.svg)
![Security](https://img.shields.io/badge/Security-AES--256-blueviolet.svg)
![Status](https://img.shields.io/badge/Status-Ready-brightgreen.svg)

## 📖 About The Project

Logging into LPU's 24online wireless network can be tedious — opening the captive portal page, entering credentials, checking the terms box, and clicking submit... **every single time** you connect to WiFi.

**LPU Wireless Auto-Login** eliminates this hassle by automating the entire login process:

- **Problem**: LPU's campus WiFi requires manual login through a web portal (`internet.lpu.in/24online`) every time you connect. This repetitive process is time-consuming, especially for students who switch between buildings or reconnect frequently.

- **Solution**: This Python-based automation tool securely stores your credentials and handles the complete login flow with a single command. It features **multi-profile support**, **AES-256 encryption**, and **optional biometric unlock**.

- **Who is this for?**: LPU students and staff who want a faster, one-click solution to authenticate with the campus WiFi network.

> 💡 **First run**: Set a master password and enter your credentials → **Every subsequent run**: Instant automatic login!

## ✨ Features

### Core Features
- 🖥️ **Modern GUI** - Clean, dark-themed interface for credential management
- 🔒 **AES-256 Encryption** - Credentials encrypted with industry-standard encryption
- 🤖 **Full Automation** - Opens browser, fills forms, clicks buttons automatically
- 🔄 **One-Click Login** - After setup, just run the script to login instantly

### Enhanced Security (v2.0)
- 👥 **Multi-Profile Support** - Store multiple WiFi credentials (personal, work, guest, etc.)
- 🔑 **Master Password Protection** - All profiles protected by a single master password
- 🖐️ **Biometric Unlock** - Optional Windows Hello support (fingerprint/face)
- 📊 **Password Strength Meter** - Visual indicator for password security
- 🔐 **PBKDF2 Key Derivation** - 480,000 iterations for brute-force resistance
- 📍 **Clear Storage Location** - Always know where your data is stored

## 📦 Installation

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install playwright keyring cryptography
```

### Step 2: Install Playwright Browsers

```bash
playwright install chromium
```

## 🚀 Usage

### Basic Usage

```bash
python lpu_auto_login.py
```

**First run**: A setup wizard will guide you through:
1. Creating a master password
2. Optionally enabling biometric unlock
3. Adding your first credential profile

**Subsequent runs**: Enter your master password → Auto-login begins!

### Command Line Options

| Command | Description |
|---------|-------------|
| `python lpu_auto_login.py` | Run with default profile |
| `python lpu_auto_login.py --gui` | Launch full GUI application |
| `python lpu_auto_login.py --profile Work` | Use a specific profile |
| `python lpu_auto_login.py --reset` | Add new credentials |
| `python lpu_auto_login.py --add-profile` | Add a new profile |
| `python lpu_auto_login.py --profiles` | List all stored profiles |
| `python lpu_auto_login.py --info` | Show security information |
| `python lpu_auto_login.py --change-master-password` | Change master password |
| `python lpu_auto_login.py --tray` | Run in system tray (background) |
| `python lpu_auto_login.py --headless` | Run browser invisibly |
| `python lpu_auto_login.py --enable-startup` | Enable Windows startup |
| `python lpu_auto_login.py --disable-startup` | Disable Windows startup |
| `python lpu_auto_login.py --legacy` | Use OS keyring (legacy mode) |
| `python lpu_auto_login.py --help` | Show all options |

### 🖥️ Full GUI Application

Launch the complete GUI with navigation between pages:

```bash
python lpu_auto_login.py --gui
```

**Features:**
- 📱 **Single window** with multi-page navigation
- ← **Back buttons** to return to previous pages
- 💾 **Save buttons** that return to profiles list
- 🔐 **Master password** setup/unlock screen
- 👤 **Profile management** with add/edit/delete
- 🔒 **Security info** page
- ♻️ **No more closing dialogs** - smooth navigation

**Navigation Flow:**
```
Unlock → Profiles → Add/Edit Profile → Back to Profiles
                 ↓
           Security Info → Back to Profiles
```


### 🖥️ Background Mode (System Tray)

Run the auto-login tool silently in your system tray:

```bash
python lpu_auto_login.py --tray
```

**Features:**
- 📶 **Auto-detects** when you connect to LPU WiFi
- 🔔 **Notifications** for login status
- 🎛️ **Tray menu** for quick actions
- 🔄 **Toggle auto-login** on/off
- 👤 **Quick profile access**

**Tray Menu Options:**
- 📶 Login Now - Manually trigger login
- 🔄 Check Connection - Force connection check
- ✅ Auto-Login Enabled - Toggle auto-login
- 👤 Manage Profiles - Open profile manager
- ℹ️ Security Info - View security details
- 🚀 Run at Startup - Toggle Windows startup
- ❌ Quit - Exit the tray app

### 🚀 Start with Windows

Enable automatic startup so you never have to manually login again:

```bash
# Enable startup
python lpu_auto_login.py --enable-startup

# Disable startup
python lpu_auto_login.py --disable-startup
```

When enabled:
1. LPU Auto-Login starts minimized in system tray when Windows boots
2. Monitors for WiFi connections
3. Automatically logs in when you connect to LPU network
4. Shows notification when login completes

### 🔇 Headless Mode

Run the browser invisibly (no visible window):

```bash
python lpu_auto_login.py --headless
```

Perfect for:
- Scheduled tasks
- Background automation
- Minimal resource usage

### Profile Management

```bash
# Add a new profile
python lpu_auto_login.py --add-profile

# List all profiles
python lpu_auto_login.py --profiles

# Use specific profile
python lpu_auto_login.py --profile "Home WiFi"

# Reset/add credentials
python lpu_auto_login.py --reset
```

## 🔒 Security

### How Credentials Are Stored

Your credentials are stored in an **encrypted SQLite database** with the following security measures:

| Feature | Implementation |
|---------|----------------|
| **Encryption** | AES-256 (Fernet - AES-128-CBC with HMAC) |
| **Key Derivation** | PBKDF2-HMAC-SHA256 with 480,000 iterations |
| **Master Password** | Never stored - only secure hash for verification |
| **Storage Location** | Platform-specific secure directory |

### Storage Locations

| Platform | Database Location |
|----------|------------------|
| **Windows** | `%APPDATA%\LPU_Wireless_Login\credentials.db` |
| **macOS** | `~/Library/Application Support/LPU_Wireless_Login/credentials.db` |
| **Linux** | `~/.config/LPU_Wireless_Login/credentials.db` |

### Security Features

✅ **AES-256 Encryption** - Military-grade encryption for all stored passwords  
✅ **Master Password Required** - Single password unlocks all profiles  
✅ **No Plain-text Storage** - Credentials never stored unencrypted  
✅ **Secure Hash Only** - Master password verified via hash, never stored  
✅ **PBKDF2 Protection** - 480,000 iterations prevent brute-force attacks  
✅ **Optional Biometrics** - Windows Hello for passwordless unlock  
✅ **Password Strength Meter** - Visual feedback on password security  

### View Security Information

```bash
python lpu_auto_login.py --info
```

This displays:
- Exact storage location
- Encryption method
- Number of stored profiles
- Biometric status

### Legacy Mode

If you prefer the simpler OS keyring storage (Windows Credential Manager, macOS Keychain):

```bash
python lpu_auto_login.py --legacy
```

## 📁 Project Structure

```
LPU_Wireless_Login/
│
├── lpu_auto_login.py      # Main automation script with multi-profile support
├── secure_credentials.py  # Encrypted credential manager
├── gui_dialogs.py         # Modern GUI components
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## ⚙️ Technical Details

### Dependencies

| Package | Purpose |
|---------|---------|
| `playwright` | Browser automation (controls Chromium) |
| `keyring` | Legacy credential storage (OS keyring API) |
| `cryptography` | AES-256 encryption & PBKDF2 key derivation |
| `tkinter` | GUI for credential input (built into Python) |

### Encryption Details

```
Master Password
      ↓
PBKDF2-HMAC-SHA256 (480,000 iterations + random salt)
      ↓
32-byte Encryption Key
      ↓
Fernet (AES-128-CBC + HMAC-SHA256)
      ↓
Encrypted Password (stored in SQLite)
```

### Browser Automation Flow

```
1. Unlock credential manager (master password / biometric)
       ↓
2. Select or auto-use default profile
       ↓
3. Launch Chromium (visible mode)
       ↓
4. Navigate to login page
       ↓
5. Find & fill username/password fields
       ↓
6. Check Terms & Conditions
       ↓
7. Click Submit/Login
       ↓
8. Keep browser open for session
```

## 🛠️ Troubleshooting

### "playwright install" fails
```bash
# Try with administrator privileges
pip install --upgrade playwright
playwright install --force
```

### "cryptography" installation fails
```bash
# Windows - Install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Linux
sudo apt-get install build-essential libssl-dev libffi-dev python3-dev
pip install cryptography
```

### Browser doesn't open
Make sure you've run `playwright install` to download browser binaries.

### Login fails / elements not found
The login page structure may have changed. Please open an issue with the error message.

### Tkinter not found (Linux)
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

### Forgot Master Password
If you forget your master password, you'll need to reset:
```bash
# Delete the credentials database (all saved passwords will be lost!)
# Windows
del "%APPDATA%\LPU_Wireless_Login\credentials.db"

# Linux/macOS
rm ~/.config/LPU_Wireless_Login/credentials.db
```

Then run the program again to set up a new master password.

## 📝 Important Notes

- 🌐 **Keep browser open** - Don't close the browser window while using the network
- 🚪 **Logout properly** - Always logout before moving to a new location
- 📊 **Usage check** - Visit https://172.20.0.66/myaccount.html to check your data usage
- 🔐 **Remember master password** - There's no recovery option if forgotten!
- 👥 **Multiple profiles** - Great for managing personal and work accounts

## 🔄 Migrating from Legacy Mode

If you were using the older keyring-based storage, the new version will automatically offer to migrate your credentials to the encrypted database on first run.

## 📜 License

This project is for educational purposes. Use responsibly and in accordance with LPU's network policies.

---

Made with ❤️ for LPU students | **Now with Enhanced Security! v2.0**

