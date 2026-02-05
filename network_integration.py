"""
Network Monitor & System Tray Integration for LPU Wireless Auto-Login
======================================================================

This module provides:
- Network connection event detection
- System tray application with status indicator
- Automatic login trigger on network connect
- Background service mode
- Windows startup integration

Features:
- Detects when system connects to WiFi networks
- Runs silently in system tray
- Shows notifications for login status
- Auto-starts with Windows (optional)
- Headless browser support

Author: Network Integration for LPU Wireless Login Automation
"""

import os
import sys
import time
import asyncio
import threading
import subprocess
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass
from enum import Enum
import ctypes
import winreg

# Check for required packages
try:
    import pystray
    from PIL import Image, ImageDraw, ImageFont
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("⚠️ System tray not available. Install with: pip install pystray pillow")

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False


# ============================================================================
# CONSTANTS
# ============================================================================

APP_NAME = "LPU Wireless Auto-Login"
STARTUP_REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_ENTRY_NAME = "LPUWirelessAutoLogin"

LPU_NETWORKS = [
    "LPU",
    "LPU-STUDENT",
    "LPU-STAFF",
    "LPU_24ONLINE",
    "LPU_WIRELESS",
    "24online"
]


# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class ConnectionStatus(Enum):
    """Network connection status."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    LOGGED_IN = "logged_in"
    ERROR = "error"


@dataclass
class NetworkInfo:
    """Information about current network connection."""
    ssid: Optional[str]
    interface_name: str
    is_connected: bool
    signal_strength: Optional[int] = None


# ============================================================================
# NETWORK DETECTION (Windows)
# ============================================================================

def get_current_wifi_ssid() -> Optional[str]:
    """
    Get the currently connected WiFi network SSID.
    
    Returns:
        SSID string if connected to WiFi, None otherwise.
    """
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'SSID' in line and 'BSSID' not in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ssid = ':'.join(parts[1:]).strip()
                        if ssid:
                            return ssid
        return None
        
    except Exception as e:
        print(f"⚠️ Error getting WiFi SSID: {e}")
        return None


def is_lpu_network(ssid: Optional[str]) -> bool:
    """
    Check if the given SSID is an LPU network.
    
    Args:
        ssid: The network SSID to check
    
    Returns:
        True if it's an LPU network, False otherwise.
    """
    if not ssid:
        return False
    
    ssid_upper = ssid.upper()
    for lpu_net in LPU_NETWORKS:
        if lpu_net.upper() in ssid_upper:
            return True
    return False


def check_internet_connectivity() -> bool:
    """
    Check if there's internet connectivity.
    
    Returns:
        True if internet is reachable, False otherwise.
    """
    try:
        result = subprocess.run(
            ['ping', '-n', '1', '-w', '2000', 'internet.lpu.in'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        return result.returncode == 0
    except Exception:
        return False


def check_captive_portal() -> bool:
    """
    Check if we're behind a captive portal (need to login).
    
    Returns:
        True if captive portal detected, False otherwise.
    """
    try:
        import urllib.request
        
        req = urllib.request.Request(
            'http://connectivitycheck.gstatic.com/generate_204',
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        response = urllib.request.urlopen(req, timeout=5)
        
        if response.status != 204:
            return True
        
        if response.url != 'http://connectivitycheck.gstatic.com/generate_204':
            return True
        
        return False
        
    except Exception:
        return True


# ============================================================================
# NETWORK EVENT MONITOR
# ============================================================================

class NetworkMonitor:
    """
    Monitor network connection events and trigger callbacks.
    
    This class watches for:
    - WiFi connection/disconnection events
    - Network interface changes
    - Captive portal detection
    """
    
    def __init__(self, on_connect: Optional[Callable] = None,
                 on_disconnect: Optional[Callable] = None,
                 check_interval: float = 5.0):
        """
        Initialize the network monitor.
        
        Args:
            on_connect: Callback when connected to LPU network
            on_disconnect: Callback when disconnected
            check_interval: Seconds between connection checks
        """
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self.check_interval = check_interval
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_ssid: Optional[str] = None
        self._last_connected = False
        self._login_attempted = False
    
    def start(self):
        """Start monitoring network events."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("🔍 Network monitor started")
    
    def stop(self):
        """Stop monitoring network events."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        print("🔍 Network monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                ssid = get_current_wifi_ssid()
                is_connected = ssid is not None
                is_lpu = is_lpu_network(ssid)
                
                if is_connected and not self._last_connected:
                    print(f"📶 Connected to WiFi: {ssid}")
                    
                    if is_lpu and not self._login_attempted:
                        time.sleep(2)
                        
                        if check_captive_portal():
                            print("🔐 Captive portal detected - login required")
                            self._login_attempted = True
                            
                            if self.on_connect:
                                try:
                                    self.on_connect(ssid)
                                except Exception as e:
                                    print(f"❌ Login callback error: {e}")
                        else:
                            print("✅ Already logged in or no captive portal")
                
                elif not is_connected and self._last_connected:
                    print("📴 WiFi disconnected")
                    self._login_attempted = False
                    
                    if self.on_disconnect:
                        try:
                            self.on_disconnect()
                        except Exception as e:
                            print(f"❌ Disconnect callback error: {e}")
                
                if ssid != self._last_ssid and ssid is not None:
                    if self._last_ssid is not None:
                        print(f"📶 Network changed: {self._last_ssid} → {ssid}")
                    self._login_attempted = False
                
                self._last_ssid = ssid
                self._last_connected = is_connected
                
            except Exception as e:
                print(f"⚠️ Monitor error: {e}")
            
            time.sleep(self.check_interval)
    
    def force_login_check(self):
        """Force a login check regardless of cached state."""
        self._login_attempted = False
        print("🔄 Forcing login check...")


# ============================================================================
# SYSTEM TRAY APPLICATION
# ============================================================================

class SystemTrayApp:
    """
    System tray application for background operation.
    
    Features:
    - Tray icon with status indicator
    - Context menu for quick actions
    - Notifications for login status
    - Toggle auto-login on/off
    """
    
    def __init__(self, login_callback: Callable, quit_callback: Optional[Callable] = None):
        """
        Initialize the system tray application.
        
        Args:
            login_callback: Function to call when login is triggered
            quit_callback: Function to call when quitting
        """
        if not TRAY_AVAILABLE:
            raise RuntimeError("System tray not available. Install pystray and pillow.")
        
        self.login_callback = login_callback
        self.quit_callback = quit_callback
        
        self.status = ConnectionStatus.DISCONNECTED
        self.auto_login_enabled = True
        self.icon: Optional[pystray.Icon] = None
        self.network_monitor: Optional[NetworkMonitor] = None
        
        self._running = False
    
    def _create_icon_image(self, status: ConnectionStatus) -> Image.Image:
        """Create a tray icon image based on status."""
        size = 64
        image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        # Colors based on status
        colors = {
            ConnectionStatus.DISCONNECTED: '#6c6c8a',  
            ConnectionStatus.CONNECTING: '#ffc107',     
            ConnectionStatus.CONNECTED: '#00b4d8',      
            ConnectionStatus.LOGGED_IN: '#00f5a0',      
            ConnectionStatus.ERROR: '#ff4757'           
        }
        
        color = colors.get(status, colors[ConnectionStatus.DISCONNECTED])
        
        center = size // 2
        
        draw.ellipse([4, 4, size-4, size-4], fill=color)
        
        inner_size = size // 3
        inner_offset = (size - inner_size) // 2
        draw.ellipse([inner_offset, inner_offset, 
                     inner_offset + inner_size, inner_offset + inner_size], 
                     fill='#1a1a2e')
        
        dot_size = size // 5
        dot_offset = (size - dot_size) // 2
        draw.ellipse([dot_offset, dot_offset, 
                     dot_offset + dot_size, dot_offset + dot_size], 
                     fill=color)
        
        return image
    
    def _create_menu(self) -> pystray.Menu:
        """Create the tray context menu."""
        return pystray.Menu(
            pystray.MenuItem(
                "📶 Login Now",
                self._on_login_now
            ),
            pystray.MenuItem(
                "🔄 Check Connection",
                self._on_check_connection
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "✅ Auto-Login Enabled" if self.auto_login_enabled else "⬜ Auto-Login Disabled",
                self._on_toggle_auto_login,
                checked=lambda item: self.auto_login_enabled
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "👤 Manage Profiles",
                self._on_manage_profiles
            ),
            pystray.MenuItem(
                "ℹ️ Security Info",
                self._on_security_info
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "🚀 Run at Startup",
                self._on_toggle_startup,
                checked=lambda item: is_startup_enabled()
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "❌ Quit",
                self._on_quit
            )
        )
    
    def _on_login_now(self):
        """Handle login now menu item."""
        self.update_status(ConnectionStatus.CONNECTING)
        self.show_notification("Logging in...", "Attempting to connect to LPU network")
        
        try:
            if self.login_callback:
                self.login_callback()
            self.update_status(ConnectionStatus.LOGGED_IN)
            self.show_notification("Login Successful", "Connected to LPU network")
        except Exception as e:
            self.update_status(ConnectionStatus.ERROR)
            self.show_notification("Login Failed", str(e))
    
    def _on_check_connection(self):
        """Force a connection check."""
        if self.network_monitor:
            self.network_monitor.force_login_check()
        
        ssid = get_current_wifi_ssid()
        if ssid:
            if check_captive_portal():
                self.show_notification("Login Required", f"Connected to {ssid}, login needed")
                self.update_status(ConnectionStatus.CONNECTED)
            else:
                self.show_notification("Connected", f"Logged in to {ssid}")
                self.update_status(ConnectionStatus.LOGGED_IN)
        else:
            self.show_notification("Disconnected", "Not connected to any WiFi network")
            self.update_status(ConnectionStatus.DISCONNECTED)
    
    def _on_toggle_auto_login(self):
        """Toggle auto-login feature."""
        self.auto_login_enabled = not self.auto_login_enabled
        status = "enabled" if self.auto_login_enabled else "disabled"
        self.show_notification("Auto-Login", f"Auto-login {status}")
        
        if self.icon:
            self.icon.menu = self._create_menu()
    
    def _on_manage_profiles(self):
        """Open profile management."""
        script_path = Path(__file__).parent / "lpu_auto_login.py"
        subprocess.Popen(
            [sys.executable, str(script_path), '--profiles'],
            creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
        )
    
    def _on_security_info(self):
        """Show security information."""
        script_path = Path(__file__).parent / "lpu_auto_login.py"
        subprocess.Popen(
            [sys.executable, str(script_path), '--info'],
            creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
        )
    
    def _on_toggle_startup(self):
        """Toggle run at startup."""
        if is_startup_enabled():
            disable_startup()
            self.show_notification("Startup Disabled", "LPU Auto-Login will not start automatically")
        else:
            enable_startup()
            self.show_notification("Startup Enabled", "LPU Auto-Login will start with Windows")
        
        if self.icon:
            self.icon.menu = self._create_menu()
    
    def _on_quit(self):
        """Quit the application."""
        self._running = False
        
        if self.network_monitor:
            self.network_monitor.stop()
        
        if self.quit_callback:
            self.quit_callback()
        
        if self.icon:
            self.icon.stop()
    
    def update_status(self, status: ConnectionStatus):
        """Update the tray icon status."""
        self.status = status
        if self.icon:
            self.icon.icon = self._create_icon_image(status)
            self.icon.title = f"LPU WiFi - {status.value.title()}"
    
    def show_notification(self, title: str, message: str):
        """Show a system notification."""
        if self.icon:
            try:
                self.icon.notify(message, title)
            except Exception:
                pass  
    
    def run(self, with_network_monitor: bool = True):
        """
        Run the system tray application.
        
        Args:
            with_network_monitor: Whether to enable network monitoring
        """
        self._running = True
        
        if with_network_monitor:
            def on_network_connect(ssid):
                if self.auto_login_enabled:
                    self._on_login_now()
                else:
                    self.show_notification(
                        "Network Connected",
                        f"Connected to {ssid}. Auto-login is disabled."
                    )
                    self.update_status(ConnectionStatus.CONNECTED)
            
            def on_network_disconnect():
                self.update_status(ConnectionStatus.DISCONNECTED)
            
            self.network_monitor = NetworkMonitor(
                on_connect=on_network_connect,
                on_disconnect=on_network_disconnect
            )
            self.network_monitor.start()
        
        ssid = get_current_wifi_ssid()
        if ssid:
            if check_captive_portal():
                self.update_status(ConnectionStatus.CONNECTED)
            else:
                self.update_status(ConnectionStatus.LOGGED_IN)
        else:
            self.update_status(ConnectionStatus.DISCONNECTED)
        
        self.icon = pystray.Icon(
            "lpu_wifi",
            self._create_icon_image(self.status),
            f"LPU WiFi - {self.status.value.title()}",
            self._create_menu()
        )
        
        print("🖥️ System tray application started")
        self.icon.run()


# ============================================================================
# WINDOWS STARTUP INTEGRATION
# ============================================================================

def get_startup_command() -> str:
    """Get the command to run at startup."""
    script_path = Path(__file__).parent / "lpu_auto_login.py"
    return f'"{sys.executable}" "{script_path}" --tray'


def is_startup_enabled() -> bool:
    """Check if the application is set to run at startup."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            STARTUP_REGISTRY_KEY,
            0,
            winreg.KEY_READ
        )
        try:
            winreg.QueryValueEx(key, STARTUP_ENTRY_NAME)
            winreg.CloseKey(key)
            return True
        except WindowsError:
            winreg.CloseKey(key)
            return False
    except Exception:
        return False


def enable_startup() -> bool:
    """Enable run at Windows startup."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            STARTUP_REGISTRY_KEY,
            0,
            winreg.KEY_SET_VALUE
        )
        
        command = get_startup_command()
        winreg.SetValueEx(key, STARTUP_ENTRY_NAME, 0, winreg.REG_SZ, command)
        winreg.CloseKey(key)
        
        print(f"✅ Startup enabled: {command}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to enable startup: {e}")
        return False


def disable_startup() -> bool:
    """Disable run at Windows startup."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            STARTUP_REGISTRY_KEY,
            0,
            winreg.KEY_SET_VALUE
        )
        
        try:
            winreg.DeleteValue(key, STARTUP_ENTRY_NAME)
        except WindowsError:
            pass  
        
        winreg.CloseKey(key)
        print("✅ Startup disabled")
        return True
        
    except Exception as e:
        print(f"❌ Failed to disable startup: {e}")
        return False


def create_scheduled_task() -> bool:
    """
    Create a Windows Task Scheduler task for more reliable startup.
    
    This is an alternative to registry startup that survives UAC prompts.
    """
    try:
        script_path = Path(__file__).parent / "lpu_auto_login.py"
        
        task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions>
    <Exec>
      <Command>"{sys.executable}"</Command>
      <Arguments>"{script_path}" --tray</Arguments>
    </Exec>
  </Actions>
</Task>'''
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False, encoding='utf-16') as f:
            f.write(task_xml)
            xml_path = f.name
        
        result = subprocess.run(
            ['schtasks', '/Create', '/TN', STARTUP_ENTRY_NAME, '/XML', xml_path, '/F'],
            capture_output=True,
            text=True
        )
        
        os.unlink(xml_path)
        
        if result.returncode == 0:
            print("✅ Scheduled task created successfully")
            return True
        else:
            print(f"❌ Failed to create scheduled task: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error creating scheduled task: {e}")
        return False


def delete_scheduled_task() -> bool:
    """Delete the Windows scheduled task."""
    try:
        result = subprocess.run(
            ['schtasks', '/Delete', '/TN', STARTUP_ENTRY_NAME, '/F'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


# ============================================================================
# HEADLESS MODE UTILITIES
# ============================================================================

def hide_console_window():
    """Hide the console window (Windows only)."""
    if sys.platform == 'win32':
        try:
            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32
            
            hwnd = kernel32.GetConsoleWindow()
            if hwnd:
                user32.ShowWindow(hwnd, 0)  
        except Exception:
            pass


def show_console_window():
    """Show the console window (Windows only)."""
    if sys.platform == 'win32':
        try:
            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32
            
            hwnd = kernel32.GetConsoleWindow()
            if hwnd:
                user32.ShowWindow(hwnd, 5)  
        except Exception:
            pass


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("🔍 Network Monitor Test")
    print("=" * 40)
    
    ssid = get_current_wifi_ssid()
    print(f"Current SSID: {ssid or 'Not connected'}")
    print(f"Is LPU network: {is_lpu_network(ssid)}")
    print(f"Captive portal: {check_captive_portal()}")
    print(f"Startup enabled: {is_startup_enabled()}")
    
    print("\n" + "=" * 40)
    print("Starting network monitor (Ctrl+C to stop)...")
    
    def on_connect(ssid):
        print(f"🔔 CALLBACK: Connected to {ssid}")
    
    def on_disconnect():
        print("🔔 CALLBACK: Disconnected")
    
    monitor = NetworkMonitor(on_connect=on_connect, on_disconnect=on_disconnect)
    monitor.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\n👋 Stopped")
