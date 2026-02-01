# 🔐 LPU Wireless Auto-Login

A Python automation tool that securely logs you into LPU's 24online wireless network with a single click!

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-Automation-green.svg)
![Status](https://img.shields.io/badge/Status-Ready-brightgreen.svg)

## 📖 About The Project

Logging into LPU's 24online wireless network can be tedious — opening the captive portal page, entering credentials, checking the terms box, and clicking submit... **every single time** you connect to WiFi.

**LPU Wireless Auto-Login** eliminates this hassle by automating the entire login process:

- **Problem**: LPU's campus WiFi requires manual login through a web portal (`internet.lpu.in/24online`) every time you connect. This repetitive process is time-consuming, especially for students who switch between buildings or reconnect frequently.

- **Solution**: This Python-based automation tool securely stores your credentials and handles the complete login flow with a single command. It uses Playwright for browser automation and the OS-native credential manager (Windows Credential Manager/macOS Keychain) for secure password storage.

- **Who is this for?**: LPU students and staff who want a faster, one-click solution to authenticate with the campus WiFi network.

> 💡 **First run**: Enter your credentials once via a sleek GUI → **Every subsequent run**: Instant automatic login!

## ✨ Features

- 🖥️ **Simple GUI** - Clean Tkinter interface for first-time credential setup
- 🔒 **Secure Storage** - Credentials stored in Windows Credential Manager (not in plain text!)
- 🤖 **Full Automation** - Opens browser, fills forms, clicks buttons automatically
- 🔄 **One-Click Login** - After setup, just run the script to login instantly
- ⚡ **Reset Option** - Easy credential reset with `--reset` flag

## 📦 Installation

### Step 1: Install Python Dependencies

```bash

pip install playwright keyring

pip install -r requirements.txt
```

### Step 2: Install Playwright Browsers

```bash
playwright install
```

> **Note**: If you only want Chromium (smaller download):
> ```bash
> playwright install chromium
> ```

## 🚀 Usage

### First Run (Credential Setup)

```bash
python lpu_auto_login.py
```

A beautiful GUI window will appear asking for your:
- **Username** - Your LPU network username
- **Password** - Your LPU network password

Your credentials are saved securely to Windows Credential Manager.

### Subsequent Runs (Auto-Login)

```bash
python lpu_auto_login.py
```

The script will:
1. ✅ Retrieve your saved credentials automatically
2. ✅ Open a Chromium browser
3. ✅ Navigate to the login page
4. ✅ Fill in your credentials
5. ✅ Accept Terms & Conditions
6. ✅ Click Login
7. ✅ Keep the browser open for your session

### Reset/Change Credentials

```bash
python lpu_auto_login.py --reset
```
or
```bash
python lpu_auto_login.py -r
```

This clears saved credentials and shows the GUI again.

## 🔒 Security

### How Credentials Are Stored

| Platform | Storage Location |
|----------|-----------------|
| **Windows** | Windows Credential Manager |
| **macOS** | macOS Keychain |
| **Linux** | Secret Service (GNOME Keyring, KWallet) |

### Security Features

✅ **No hardcoded passwords** - Credentials are never stored in the code  
✅ **Encrypted storage** - Uses OS-level encryption  
✅ **No plain-text logs** - Passwords are masked in all output  
✅ **Secure input** - Password field is masked in GUI

### View/Manage Stored Credentials (Windows)

1. Open **Control Panel**
2. Go to **User Accounts** → **Credential Manager**
3. Click **Windows Credentials**
4. Look for entries starting with `LPU_Wireless_24Online`

## 📁 Project Structure

```
LPU_Wireless_Login/
│
├── lpu_auto_login.py    # Main automation script
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## ⚙️ Technical Details

### Dependencies

| Package | Purpose |
|---------|---------|
| `playwright` | Browser automation (controls Chromium) |
| `keyring` | Secure credential storage (OS keyring API) |
| `tkinter` | GUI for credential input (built into Python) |

### Browser Automation Flow

```
1. Launch Chromium (visible mode)
       ↓
2. Navigate to login page
       ↓
3. Wait for page load
       ↓
4. Find & fill username field
       ↓
5. Find & fill password field
       ↓
6. Check Terms & Conditions
       ↓
7. Click Submit/Login
       ↓
8. Wait for success
       ↓
9. Keep browser open
```

## 🛠️ Troubleshooting

### "playwright install" fails
```bash
# Try with administrator privileges
pip install --upgrade playwright
playwright install --force
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

### Keyring backend errors (Linux)
```bash
# Install a keyring backend
sudo apt-get install gnome-keyring
# or
pip install keyrings.alt
```

## 📝 Important Notes

- 🌐 **Keep browser open** - Don't close the browser window while using the network
- 🚪 **Logout properly** - Always logout before moving to a new location
- 📊 **Usage check** - Visit https://172.20.0.66/myaccount.html to check your data usage

## 📜 License

This project is for educational purposes. Use responsibly and in accordance with LPU's network policies.

---

Made with ❤️ for LPU students
