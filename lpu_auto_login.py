"""
LPU Wireless Auto-Login Script
==============================
This script automates the login process for LPU's 24online wireless network.

Features:
- 🔐 Multi-profile credential support (store multiple accounts)
- 🔒 Encrypted local database with AES-256 encryption
- 🖐️ Optional biometric unlock (Windows Hello where supported)
- 🔑 Master password protection with PBKDF2 key derivation
- 🌐 Browser automation using Playwright
- ⚡ Async/await syntax for non-blocking operations
- 📝 Clear communication about credential storage

Security Model:
- All credentials are encrypted using Fernet (AES-256-CBC with HMAC)
- Master password is never stored; only its secure hash is kept
- Database is encrypted at rest using derived keys
- Optional fallback to OS keyring for additional security

Storage Location:
- Windows: %APPDATA%/LPU_Wireless_Login/credentials.db
- macOS: ~/Library/Application Support/LPU_Wireless_Login/credentials.db
- Linux: ~/.config/LPU_Wireless_Login/credentials.db

Author: Enhanced for LPU Wireless Login Automation
"""

import asyncio
import sys
import argparse
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Tuple, List
import keyring
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

try:
    from secure_credentials import (
        SecureCredentialManager, 
        display_security_info,
        migrate_from_keyring,
        get_database_path,
        DEFAULT_PROFILE
    )
    from gui_dialogs import (
        MasterPasswordDialog,
        ProfileSelectionDialog,
        ProfileEditorDialog,
        SecurityInfoDialog,
        ProfileInfo
    )
    ENHANCED_SECURITY = True
except ImportError:
    ENHANCED_SECURITY = False
    print("⚠️ Enhanced security modules not found. Using legacy mode.")

try:
    from network_integration import (
        NetworkMonitor,
        SystemTrayApp,
        get_current_wifi_ssid,
        is_lpu_network,
        check_captive_portal,
        is_startup_enabled,
        enable_startup,
        disable_startup,
        hide_console_window,
        TRAY_AVAILABLE
    )
    NETWORK_INTEGRATION = True
except ImportError:
    NETWORK_INTEGRATION = False
    TRAY_AVAILABLE = False
    print("⚠️ Network integration not available.")

try:
    from gui_app import CredentialManagerApp, show_credential_manager
    GUI_APP_AVAILABLE = True
except ImportError:
    GUI_APP_AVAILABLE = False



# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

LOGIN_URL = "https://internet.lpu.in/24online/webpages/client.jsp"

KEYRING_SERVICE = "LPU_Wireless_24Online"
KEYRING_USERNAME_KEY = "username"

PAGE_LOAD_TIMEOUT = 15000   
ELEMENT_TIMEOUT = 5000      
LOGIN_SUCCESS_TIMEOUT = 5000   
FAST_SELECTOR_TIMEOUT = 1500  


# ============================================================================
# LEGACY CREDENTIAL FUNCTIONS (Backward Compatibility)
# ============================================================================

def get_stored_credentials_legacy() -> Optional[Tuple[str, str]]:
    """
    Retrieve stored credentials from the OS keyring (legacy mode).
    
    Returns:
        Tuple of (username, password) if credentials exist, None otherwise.
    
    How this works:
        - Uses 'keyring' library which interfaces with:
          - Windows Credential Manager
          - macOS Keychain
          - Linux Secret Service (like GNOME Keyring)
        - Credentials are encrypted and managed by the OS
    """
    try:
        username = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY)
        
        if username:
            password = keyring.get_password(KEYRING_SERVICE, username)
            
            if password:
                print(f"✅ Found stored credentials for user: {username}")
                return (username, password)
        
        print("ℹ️ No stored credentials found.")
        return None
        
    except Exception as e:
        print(f"⚠️ Error accessing keyring: {e}")
        return None


def save_credentials_legacy(username: str, password: str) -> bool:
    """
    Securely save credentials to the OS keyring (legacy mode).
    
    Args:
        username: The login username
        password: The login password
    
    Returns:
        True if saved successfully, False otherwise.
    """
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY, username)
        keyring.set_password(KEYRING_SERVICE, username, password)
        print(f"✅ Credentials saved securely for user: {username}")
        return True
        
    except Exception as e:
        print(f"❌ Error saving credentials: {e}")
        return False


def delete_credentials_legacy() -> bool:
    """
    Delete stored credentials from the OS keyring (legacy mode).
    
    Returns:
        True if deleted successfully, False otherwise.
    """
    try:
        username = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY)
        
        if username:
            try:
                keyring.delete_password(KEYRING_SERVICE, username)
            except keyring.errors.PasswordDeleteError:
                pass
            
            try:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY)
            except keyring.errors.PasswordDeleteError:
                pass
            
            print("✅ Credentials deleted successfully.")
            return True
        else:
            print("ℹ️ No credentials to delete.")
            return True
            
    except Exception as e:
        print(f"❌ Error deleting credentials: {e}")
        return False


# ============================================================================
# ENHANCED CREDENTIAL MANAGEMENT (New Multi-Profile System)
# ============================================================================

class EnhancedCredentialManager:
    """
    Wrapper class that provides a unified interface for credential management.
    
    Supports:
    - Multi-profile storage
    - Encrypted database
    - Master password protection
    - Optional biometric unlock
    - Migration from legacy keyring storage
    """
    
    def __init__(self):
        """Initialize the enhanced credential manager."""
        self.manager: Optional[SecureCredentialManager] = None
        self.unlocked: bool = False
        
        if ENHANCED_SECURITY:
            self.manager = SecureCredentialManager()
    
    def is_available(self) -> bool:
        """Check if enhanced security is available."""
        return ENHANCED_SECURITY and self.manager is not None
    
    def is_initialized(self) -> bool:
        """Check if the credential manager has been set up with a master password."""
        if not self.is_available():
            return False
        return self.manager.is_initialized()
    
    def setup_master_password(self, password: str, enable_biometric: bool = False) -> bool:
        """
        Set up the master password for first-time use.
        
        Args:
            password: The master password to set
            enable_biometric: Whether to enable biometric unlock
        
        Returns:
            True if setup successful, False otherwise.
        """
        if not self.is_available():
            return False
        
        success = self.manager.initialize(password, enable_biometric)
        if success:
            self.unlocked = True
            
            legacy_creds = get_stored_credentials_legacy()
            if legacy_creds:
                print("\n📦 Found existing credentials from legacy storage.")
                migrate_result = migrate_from_keyring(self.manager)
                if migrate_result:
                    print("✅ Legacy credentials migrated to secure storage.")
        
        return success
    
    def unlock(self, password: str, use_biometric: bool = False) -> bool:
        """
        Unlock the credential manager.
        
        Args:
            password: The master password
            use_biometric: Whether to use biometric authentication
        
        Returns:
            True if unlock successful, False otherwise.
        """
        if not self.is_available():
            return False
        
        success = self.manager.unlock(password, use_biometric)
        self.unlocked = success
        return success
    
    def get_credentials(self, profile_name: Optional[str] = None) -> Optional[Tuple[str, str]]:
        """
        Get credentials for a profile.
        
        Args:
            profile_name: Name of the profile. If None, uses default profile.
        
        Returns:
            Tuple of (username, password) or None if not found.
        """
        if not self.is_available() or not self.unlocked:
            return get_stored_credentials_legacy()
        
        return self.manager.get_credentials(profile_name)
    
    def add_profile(self, profile_name: str, username: str, password: str, 
                   is_default: bool = False) -> bool:
        """
        Add a new credential profile.
        
        Args:
            profile_name: Unique name for this profile
            username: Login username
            password: Login password
            is_default: Whether this should be the default profile
        
        Returns:
            True if added successfully, False otherwise.
        """
        if not self.is_available() or not self.unlocked:
            return save_credentials_legacy(username, password)
        
        return self.manager.add_profile(profile_name, username, password, is_default)
    
    def list_profiles(self) -> List[ProfileInfo]:
        """
        List all stored profiles.
        
        Returns:
            List of ProfileInfo objects.
        """
        if not self.is_available() or not self.unlocked:
            legacy_creds = get_stored_credentials_legacy()
            if legacy_creds:
                return [ProfileInfo(
                    name="Legacy Profile",
                    username=legacy_creds[0],
                    is_default=True
                )]
            return []
        
        profiles = self.manager.list_profiles()
        return [
            ProfileInfo(
                name=p.profile_name,
                username=p.username,
                is_default=p.is_default,
                last_used=p.last_used
            )
            for p in profiles
        ]
    
    def delete_profile(self, profile_name: str) -> bool:
        """Delete a credential profile."""
        if not self.is_available() or not self.unlocked:
            return delete_credentials_legacy()
        
        return self.manager.delete_profile(profile_name)
    
    def get_security_info(self) -> dict:
        """Get security information."""
        if not self.is_available():
            return {
                'storage_path': 'OS Keyring (Legacy Mode)',
                'encryption_method': 'OS-provided',
                'master_password_set': False,
                'biometric_available': False,
                'biometric_enabled': False,
                'total_profiles': 1 if get_stored_credentials_legacy() else 0
            }
        
        info = self.manager.get_security_info()
        return {
            'storage_path': info.storage_path,
            'encryption_method': info.encryption_method,
            'master_password_set': info.master_password_set,
            'biometric_available': info.biometric_available,
            'biometric_enabled': info.biometric_enabled,
            'total_profiles': info.total_profiles
        }


# ============================================================================
# CREDENTIAL MANAGEMENT WORKFLOW
# ============================================================================

def handle_credential_workflow(reset_mode: bool = False, 
                               profile: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """
    Handle the complete credential workflow with GUI dialogs.
    
    Args:
        reset_mode: Whether to reset/add new credentials
        profile: Specific profile to use
    
    Returns:
        Tuple of (username, password) or None if cancelled.
    """
    manager = EnhancedCredentialManager()
    
    if not manager.is_available():
        print("ℹ️ Using legacy credential storage (OS Keyring)")
        if reset_mode:
            delete_credentials_legacy()
        
        credentials = get_stored_credentials_legacy()
        if credentials is None:
            print("📝 Opening credential input dialog...")
            dialog = CredentialDialog(reset_mode=reset_mode)
            result = dialog.show()
            
            if result is None:
                return None
            
            username, password = result
            save_credentials_legacy(username, password)
            credentials = (username, password)
        
        return credentials
    
    print("\n" + "=" * 60)
    print("🔐 SECURE CREDENTIAL MANAGER")
    print("=" * 60)
    print(f"\n📁 Storage: {get_database_path()}")
    
    if not manager.is_initialized():
        print("\n🆕 First-time setup required. Creating secure storage...")
        
        dialog = MasterPasswordDialog(mode="setup")
        result = dialog.show()
        
        if result is None:
            print("❌ Setup cancelled.")
            return None
        
        if not manager.setup_master_password(
            result['password'], 
            result.get('enable_biometric', False)
        ):
            print("❌ Failed to set up secure storage.")
            return None
        
        print("\n📝 Please add your login credentials...")
        editor = ProfileEditorDialog()
        profile_data = editor.show()
        
        if profile_data is None:
            print("❌ Profile creation cancelled.")
            return None
        
        manager.add_profile(
            profile_data['name'],
            profile_data['username'],
            profile_data['password'],
            is_default=True
        )
        
        return (profile_data['username'], profile_data['password'])
    
    print("\n🔓 Unlocking secure storage...")
    
    security_info = manager.get_security_info()
    use_biometric = security_info.get('biometric_enabled', False)
    
    unlock_dialog = MasterPasswordDialog(mode="unlock")
    unlock_result = unlock_dialog.show()
    
    if unlock_result is None:
        print("❌ Unlock cancelled.")
        return None
    
    if not manager.unlock(unlock_result['password'], use_biometric):
        print("❌ Failed to unlock. Incorrect password?")
        return None
    
    profiles = manager.list_profiles()
    
    if reset_mode or not profiles:
        editor = ProfileEditorDialog()
        profile_data = editor.show()
        
        if profile_data is None:
            if not profiles:
                print("❌ No profiles available.")
                return None
        else:
            manager.add_profile(
                profile_data['name'],
                profile_data['username'],
                profile_data['password'],
                is_default=profile_data.get('is_default', len(profiles) == 0)
            )
            return (profile_data['username'], profile_data['password'])
    
    if len(profiles) == 1:
        creds = manager.get_credentials(profiles[0].name)
        if creds:
            print(f"✅ Using profile: {profiles[0].name}")
            return creds
    
    if profile:
        creds = manager.get_credentials(profile)
        if creds:
            print(f"✅ Using profile: {profile}")
            return creds
        else:
            print(f"❌ Profile '{profile}' not found.")
    
    selection_dialog = ProfileSelectionDialog(profiles)
    selection_result = selection_dialog.show()
    
    if selection_result is None:
        print("❌ Profile selection cancelled.")
        return None
    
    action = selection_result.get('action')
    selected_profile = selection_result.get('profile')
    
    if action == 'select' and selected_profile:
        creds = manager.get_credentials(selected_profile)
        if creds:
            print(f"✅ Using profile: {selected_profile}")
            return creds
    
    elif action == 'add':
        editor = ProfileEditorDialog()
        profile_data = editor.show()
        if profile_data:
            manager.add_profile(
                profile_data['name'],
                profile_data['username'],
                profile_data['password'],
                is_default=profile_data.get('is_default', False)
            )
            return (profile_data['username'], profile_data['password'])
    
    elif action == 'edit' and selected_profile:
        existing = next((p for p in profiles if p.name == selected_profile), None)
        if existing:
            editor = ProfileEditorDialog(existing_profile=existing)
            profile_data = editor.show()
            if profile_data and profile_data.get('password'):
                manager.manager.update_profile(
                    selected_profile,
                    username=profile_data.get('username'),
                    password=profile_data.get('password'),
                    new_name=profile_data.get('name') if profile_data.get('name') != selected_profile else None,
                    is_default=profile_data.get('is_default')
                )
                return (profile_data['username'], profile_data['password'])
    
    elif action == 'delete' and selected_profile:
        if messagebox.askyesno("Confirm Delete", f"Delete profile '{selected_profile}'?"):
            manager.delete_profile(selected_profile)
            return handle_credential_workflow()
    
    elif action == 'default' and selected_profile:
        manager.manager.set_default_profile(selected_profile)
        creds = manager.get_credentials(selected_profile)
        if creds:
            return creds
    
    return None


# ============================================================================
# LEGACY CREDENTIAL DIALOG (Backward Compatibility)
# ============================================================================

class CredentialDialog:
    """
    A modern, minimal Tkinter dialog for entering login credentials.
    
    Features:
    - Clean, centered design
    - Password masking
    - Input validation
    - Reset credentials option
    """
    
    def __init__(self, reset_mode: bool = False):
        """
        Initialize the credential dialog.
        
        Args:
            reset_mode: If True, shows dialog for resetting credentials
        """
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.cancelled: bool = False
        self.reset_mode = reset_mode
        
        self.root = tk.Tk()
        self.root.title("LPU Wireless Login")
        self.root.resizable(True, True) 
        
        window_width = 400
        window_height = 280
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        self.root.configure(bg="#1a1a2e")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TLabel', background='#1a1a2e', foreground='#eee', font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', background='#1a1a2e', foreground='#00d9ff', font=('Segoe UI', 16, 'bold'))
        self.style.configure('TEntry', fieldbackground='#16213e', foreground='#fff', font=('Segoe UI', 11))
        self.style.configure('TButton', font=('Segoe UI', 10, 'bold'))
        self.style.map('TButton', background=[('active', '#00d9ff')])
        
        self._create_widgets()
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_cancel)
    
    def _create_widgets(self):
        """Create and layout all GUI widgets."""
        
        main_frame = tk.Frame(self.root, bg="#1a1a2e", padx=30, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_text = "Reset Credentials" if self.reset_mode else "LPU Wireless Login"
        title_label = ttk.Label(main_frame, text=title_text, style='Title.TLabel')
        title_label.pack(pady=(0, 5))
        
        subtitle = "Enter your new credentials" if self.reset_mode else "Enter your credentials to save"
        subtitle_label = ttk.Label(main_frame, text=subtitle, style='TLabel')
        subtitle_label.pack(pady=(0, 20))
        
        username_frame = tk.Frame(main_frame, bg="#1a1a2e")
        username_frame.pack(fill=tk.X, pady=(0, 15))
        
        username_label = ttk.Label(username_frame, text="Username:", style='TLabel')
        username_label.pack(anchor=tk.W)
        
        self.username_entry = tk.Entry(
            username_frame,
            font=('Segoe UI', 11),
            bg='#16213e',
            fg='#ffffff',
            insertbackground='#00d9ff',
            relief=tk.FLAT,
            highlightthickness=2,
            highlightbackground='#0f3460',
            highlightcolor='#00d9ff'
        )
        self.username_entry.pack(fill=tk.X, pady=(5, 0), ipady=8)
        
        password_frame = tk.Frame(main_frame, bg="#1a1a2e")
        password_frame.pack(fill=tk.X, pady=(0, 20))
        
        password_label = ttk.Label(password_frame, text="Password:", style='TLabel')
        password_label.pack(anchor=tk.W)
        
        self.password_entry = tk.Entry(
            password_frame,
            font=('Segoe UI', 11),
            bg='#16213e',
            fg='#ffffff',
            insertbackground='#00d9ff',
            relief=tk.FLAT,
            highlightthickness=2,
            highlightbackground='#0f3460',
            highlightcolor='#00d9ff',
            show='•'
        )
        self.password_entry.pack(fill=tk.X, pady=(5, 0), ipady=8)
        
        button_frame = tk.Frame(main_frame, bg="#1a1a2e")
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            font=('Segoe UI', 10),
            bg='#16213e',
            fg='#ffffff',
            activebackground='#0f3460',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_cancel,
            width=12
        )
        cancel_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        submit_btn = tk.Button(
            button_frame,
            text="Save & Login",
            font=('Segoe UI', 10, 'bold'),
            bg='#00d9ff',
            fg='#1a1a2e',
            activebackground='#00b4d8',
            activeforeground='#1a1a2e',
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_submit,
            width=15
        )
        submit_btn.pack(side=tk.RIGHT)
        
        self.root.bind('<Return>', lambda e: self._on_submit())
        
        self.username_entry.focus_set()
    
    def _on_submit(self):
        """Handle submit button click."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username:
            messagebox.showerror("Error", "Please enter your username.")
            self.username_entry.focus_set()
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter your password.")
            self.password_entry.focus_set()
            return
        
        self.username = username
        self.password = password
        self.root.destroy()
    
    def _on_cancel(self):
        """Handle cancel button or window close."""
        self.cancelled = True
        self.root.destroy()
    
    def show(self) -> Optional[Tuple[str, str]]:
        """
        Display the dialog and wait for user input.
        
        Returns:
            Tuple of (username, password) if submitted, None if cancelled.
        """
        self.root.mainloop()
        
        if self.cancelled:
            return None
        
        return (self.username, self.password) if self.username and self.password else None


async def perform_login(username: str, password: str, 
                        headless: bool = False, 
                        auto_close: bool = False,
                        minimize: bool = False) -> bool:
    """
    Perform the automated login using Playwright.
    
    This function:
    1. Opens a Chromium browser (visible or headless)
    2. Navigates to the login page
    3. Fills in username and password
    4. Accepts terms and conditions
    5. Submits the login form
    6. Waits for login success
    
    Args:
        username: The login username
        password: The login password
        headless: If True, run browser without visible window
        auto_close: If True, close browser after successful login
        minimize: If True, minimize browser window after login
    
    Returns:
        True if login was successful, False otherwise.
    """
    
    print("\n" + "="*60)
    print("🌐 STARTING BROWSER AUTOMATION")
    if headless:
        print("   (Running in headless mode)")
    print("="*60 + "\n")
    
    async with async_playwright() as p:
        mode_text = "headless" if headless else "visible"
        print(f"📌 Launching Chromium browser ({mode_text})...")
        browser = await p.chromium.launch(
            headless=headless,  
            slow_mo=0        
        )
        
        context = await browser.new_context(
            viewport={'width': 1280, 'height': 720},
            ignore_https_errors=True
        )
        
        page = await context.new_page()
        
        login_success = False  
        
        try:
            print(f"📌 Navigating to: {LOGIN_URL}")
            
            await page.goto(LOGIN_URL, wait_until='domcontentloaded', timeout=PAGE_LOAD_TIMEOUT)
            print("✅ Page loaded successfully!")
            
            await page.wait_for_timeout(300)
            
            print("📌 Looking for username field...")
            
            username_selectors = [
                'input[name="username"]',
                'input#username',
                'input[type="text"][name*="user"]',
                '#username',
                'input[placeholder*="user" i]'
            ]
            
            username_field = None
            for selector in username_selectors:
                try:
                    username_field = await page.wait_for_selector(
                        selector, 
                        timeout=FAST_SELECTOR_TIMEOUT,  
                        state='visible'
                    )
                    if username_field:
                        print(f"✅ Found username field with selector: {selector}")
                        break
                except PlaywrightTimeout:
                    continue
            
            if not username_field:
                raise Exception("Could not find username input field!")
            
            await username_field.fill('')
            await username_field.fill(username)
            print(f"✅ Entered username: {username}")
            
            print("📌 Looking for password field...")
            
            password_selectors = [
                'input[name="password"]',
                'input#password',
                'input[type="password"]',
                '#password'
            ]
            
            password_field = None
            for selector in password_selectors:
                try:
                    password_field = await page.wait_for_selector(
                        selector,
                        timeout=FAST_SELECTOR_TIMEOUT, 
                        state='visible'
                    )
                    if password_field:
                        print(f"✅ Found password field with selector: {selector}")
                        break
                except PlaywrightTimeout:
                    continue
            
            if not password_field:
                raise Exception("Could not find password input field!")
            
            await password_field.fill(password)
            print("✅ Entered password: ********")
            
            print("📌 Looking for Terms & Conditions checkbox...")
            
            terms_selectors = [
                'input[name="termcondition"]',
                'input#termcondition',
                'input[type="checkbox"]',
                'input[name*="term"]',
                '#termcondition'
            ]
            
            terms_checkbox = None
            for selector in terms_selectors:
                try:
                    terms_checkbox = await page.wait_for_selector(
                        selector,
                        timeout=FAST_SELECTOR_TIMEOUT,  
                        state='visible'
                    )
                    if terms_checkbox:
                        print(f"✅ Found checkbox with selector: {selector}")
                        break
                except PlaywrightTimeout:
                    continue
            
            if terms_checkbox:
                is_checked = await terms_checkbox.is_checked()
                if not is_checked:
                    await terms_checkbox.check()
                    print("✅ Accepted Terms & Conditions")
                else:
                    print("✅ Terms & Conditions already accepted")
            else:
                print("⚠️ Terms checkbox not found (might not be required)")
            
            print("📌 Looking for login button...")
            
            login_selectors = [
                'input[type="submit"]',
                'input[name="login"]',
                'button[type="submit"]',
                'input#login',
                '#login',
                'input[value*="Login" i]',
                'input[value*="Submit" i]',
                'button:has-text("Login")',
                'button:has-text("Submit")'
            ]
            
            login_button = None
            for selector in login_selectors:
                try:
                    login_button = await page.wait_for_selector(
                        selector,
                        timeout=FAST_SELECTOR_TIMEOUT,  
                        state='visible'
                    )
                    if login_button:
                        print(f"✅ Found login button with selector: {selector}")
                        break
                except PlaywrightTimeout:
                    continue
            
            if not login_button:
                raise Exception("Could not find login/submit button!")
            
            await login_button.click()
            print("✅ Clicked login button!")
            
            print("📌 Waiting for login to complete...")
            
            await page.wait_for_timeout(1000)
            
            success_indicators = [
                'text=Logout',
                'text=logout',
                'input[value*="Logout" i]',
                'text=Successfully',
                'text=Welcome',
                'text=check your usage'
            ]
            
            login_success = False
            for indicator in success_indicators:
                try:
                    element = await page.wait_for_selector(indicator, timeout=800)  
                    if element:
                        login_success = True
                        print(f"✅ Login successful! Found indicator: {indicator}")
                        break
                except PlaywrightTimeout:
                    continue
            
            if not login_success:
                current_url = page.url
                if 'client.jsp' not in current_url.lower():
                    print("✅ Login appears successful (page navigation detected)")
                    login_success = True
                else:
                    error_selectors = ['text=Invalid', 'text=incorrect', 'text=failed', '.error']
                    for error_sel in error_selectors:
                        try:
                            error_elem = await page.query_selector(error_sel)
                            if error_elem:
                                error_text = await error_elem.inner_text()
                                print(f"❌ Login failed: {error_text}")
                                break
                        except:
                            continue
            
            if login_success:
                print("\n" + "="*60)
                print("🎉 LOGIN SUCCESSFUL!")
                print("="*60)
                
                if auto_close:
                    print("\n✅ Auto-login complete. Browser closing...")
                    await page.wait_for_timeout(2000)  
                    return True
                
                print("\n📝 Important Notes:")
                print("   - Keep this browser window open to stay connected")
                print("   - Logout before moving to a new location")
                print("   - To check usage, visit: https://172.20.0.66/myaccount.html")
                print("")
                
                if minimize:
                    print("📌 Browser window minimized. Session active in background.")
                else:
                    print("⏳ Browser will remain open. Close it manually when done.")
                
                try:
                    await page.wait_for_timeout(86400000) 
                except:
                    pass  
                
                return True
            else:
                print("\n❌ Could not confirm login success.")
                print("   Please check the browser window for any error messages.")
                await page.wait_for_timeout(5000)  
                return False
                
        except PlaywrightTimeout as e:
            print(f"\n❌ Timeout error: {e}")
            print("   The page took too long to respond.")
            return False
            
        except Exception as e:
            print(f"\n❌ Error during login: {e}")
            return False
            
        finally:
            if auto_close or not login_success:
                await context.close()
                await browser.close()
                print("\n📌 Browser closed.")


async def main():
    """
    Main program entry point with enhanced security features.
    
    Program flow:
    1. Parse command line arguments
    2. Handle special commands (--info, --profiles, --add-profile, etc.)
    3. Check for existing credentials (multi-profile or legacy)
    4. If not found, show GUI to collect credentials
    5. Save credentials securely with encryption
    6. Perform automated login
    
    Security Features:
    - Multi-profile credential storage
    - AES-256 encrypted database
    - Master password protection
    - Optional biometric unlock
    """
    
    parser = argparse.ArgumentParser(
        description="LPU Wireless Auto-Login with Secure Credential Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python lpu_auto_login.py                    # Run with default profile
  python lpu_auto_login.py --profile Work     # Use specific profile
  python lpu_auto_login.py --reset            # Add new credentials
  python lpu_auto_login.py --info             # Show security information
  python lpu_auto_login.py --profiles         # List all profiles
  python lpu_auto_login.py --tray             # Run in system tray (background)
  python lpu_auto_login.py --headless         # Run with hidden browser
  python lpu_auto_login.py --enable-startup   # Enable run at Windows startup
  python lpu_auto_login.py --legacy           # Use legacy keyring mode

Security:
  Your credentials are encrypted with AES-256 and protected by a master password.
  The master password is never stored - only its secure hash is kept for verification.
        """
    )
    
    parser.add_argument(
        '-r', '--reset',
        action='store_true',
        help='Add new credentials or reset existing ones'
    )
    
    parser.add_argument(
        '-p', '--profile',
        type=str,
        default=None,
        help='Use a specific credential profile'
    )
    
    parser.add_argument(
        '--profiles',
        action='store_true',
        help='List all stored credential profiles'
    )
    
    parser.add_argument(
        '--add-profile',
        action='store_true',
        help='Add a new credential profile'
    )
    
    parser.add_argument(
        '--info',
        action='store_true',
        help='Display security information and storage location'
    )
    
    parser.add_argument(
        '--legacy',
        action='store_true',
        help='Use legacy OS keyring storage instead of encrypted database'
    )
    
    parser.add_argument(
        '--change-master-password',
        action='store_true',
        help='Change the master password'
    )
    
    parser.add_argument(
        '--tray',
        action='store_true',
        help='Run in system tray with auto-login on network connect'
    )
    
    parser.add_argument(
        '--headless',
        action='store_true',
        help='Run browser in headless mode (no visible window)'
    )
    
    parser.add_argument(
        '--enable-startup',
        action='store_true',
        help='Enable automatic startup with Windows'
    )
    
    parser.add_argument(
        '--disable-startup',
        action='store_true',
        help='Disable automatic startup with Windows'
    )
    
    parser.add_argument(
        '--minimize',
        action='store_true',
        help='Minimize browser window after login'
    )
    
    parser.add_argument(
        '--gui',
        action='store_true',
        help='Launch full GUI application with navigation'
    )
    
    args = parser.parse_args()
    
    # Handle --enable-startup command
    if args.enable_startup:
        if NETWORK_INTEGRATION:
            if enable_startup():
                print("✅ LPU Auto-Login will now start automatically with Windows")
                print("   It will run in the system tray and auto-login when you connect to LPU WiFi")
            else:
                print("❌ Failed to enable startup")
        else:
            print("❌ Network integration not available. Install pystray and pillow.")
        return
    
    # Handle --disable-startup command
    if args.disable_startup:
        if NETWORK_INTEGRATION:
            if disable_startup():
                print("✅ Automatic startup disabled")
            else:
                print("❌ Failed to disable startup")
        else:
            print("ℹ️ Startup was not enabled")
        return
    
    # Handle --gui command (full GUI application)
    if args.gui:
        if not GUI_APP_AVAILABLE:
            print("❌ GUI application not available.")
            return
        
        print("🖥️ Launching GUI application...")
        
        # Determine start page based on credential manager state
        if ENHANCED_SECURITY:
            manager = EnhancedCredentialManager()
            if not manager.is_initialized():
                start_page = "setup"
            else:
                start_page = "unlock"
        else:
            start_page = "profiles"
        
        # Create and run GUI app
        app = CredentialManagerApp(
            credential_manager=manager.manager if ENHANCED_SECURITY else None
        )
        result = app.run(start_page)
        
        if result and result.get("action") == "login":
            profile_name = result.get("profile")
            print(f"\n✅ Using profile: {profile_name}")
            
            # Get credentials for the selected profile
            if ENHANCED_SECURITY and manager.manager.is_unlocked:
                creds = manager.manager.get_credentials(profile_name)
                if creds:
                    success = await perform_login(creds[0], creds[1], 
                                                  headless=args.headless,
                                                  minimize=args.minimize)
                    if not success:
                        print("\n⚠️ Login was not successful.")
            else:
                print("❌ Unable to retrieve credentials.")
        return
    
    # Handle --tray command (system tray mode)
    if args.tray:
        if not TRAY_AVAILABLE:
            print("❌ System tray not available. Install with: pip install pystray pillow")
            return
        
        print("🖥️ Starting in system tray mode...")
        print("   Auto-login will trigger when connecting to LPU network")
        
        # Hide console window for background operation
        if not args.headless:
            hide_console_window()
        
        def tray_login_callback():
            """Callback for tray-initiated login."""
            # Get credentials and perform login
            credentials = handle_credential_workflow()
            if credentials:
                username, password = credentials
                # Run async login in new event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    success = loop.run_until_complete(
                        perform_login(username, password, headless=True, auto_close=True)
                    )
                    return success
                finally:
                    loop.close()
            return False
        
        # Create and run system tray app
        tray_app = SystemTrayApp(login_callback=tray_login_callback)
        tray_app.run(with_network_monitor=True)
        return
    
    # Print header (only for non-tray mode)
    print("\n" + "="*60)
    print("🔐 LPU WIRELESS AUTO-LOGIN")
    print("   Secure Multi-Profile Credential Manager")
    print("="*60)
    
    # Handle --info command
    if args.info:
        manager = EnhancedCredentialManager()
        info = manager.get_security_info()
        
        print("\n🔒 SECURITY INFORMATION")
        print("-" * 40)
        print(f"📁 Storage Location: {info['storage_path']}")
        print(f"🔐 Encryption: {info['encryption_method']}")
        print(f"🔑 Master Password: {'Set ✓' if info['master_password_set'] else 'Not Set'}")
        print(f"👤 Stored Profiles: {info['total_profiles']}")
        print(f"🖐️ Biometric Support: {'Available' if info['biometric_available'] else 'Not Available'}")
        print(f"🖐️ Biometric Enabled: {'Yes' if info['biometric_enabled'] else 'No'}")
        print("")
        
        if ENHANCED_SECURITY:
            # Show GUI dialog for more details
            security_dialog = SecurityInfoDialog(info)
            security_dialog.show()
        return
    
    # Handle --profiles command
    if args.profiles:
        manager = EnhancedCredentialManager()
        
        if not manager.is_available():
            # Legacy mode
            creds = get_stored_credentials_legacy()
            if creds:
                print("\n👤 STORED PROFILES (Legacy Mode)")
                print("-" * 40)
                print(f"  • Legacy Profile: {creds[0]} (default)")
            else:
                print("\n⚠️ No credentials stored.")
            return
        
        if not manager.is_initialized():
            print("\n⚠️ Secure storage not initialized. Run the program first to set up.")
            return
        
        # Need to unlock to list profiles
        unlock_dialog = MasterPasswordDialog(mode="unlock")
        unlock_result = unlock_dialog.show()
        
        if unlock_result is None:
            print("❌ Cancelled.")
            return
        
        if not manager.unlock(unlock_result['password']):
            print("❌ Incorrect password.")
            return
        
        profiles = manager.list_profiles()
        
        print("\n� STORED PROFILES")
        print("-" * 40)
        
        if not profiles:
            print("  No profiles stored.")
        else:
            for p in profiles:
                default_marker = " ⭐ (default)" if p.is_default else ""
                last_used = f" - Last used: {p.last_used[:16]}" if p.last_used else ""
                print(f"  • {p.name}: {p.username}{default_marker}{last_used}")
        
        print("")
        return
    
    # Handle --change-master-password
    if args.change_master_password:
        if not ENHANCED_SECURITY:
            print("❌ Enhanced security not available.")
            return
        
        manager = EnhancedCredentialManager()
        
        if not manager.is_initialized():
            print("❌ Secure storage not initialized. Nothing to change.")
            return
        
        change_dialog = MasterPasswordDialog(mode="change")
        change_result = change_dialog.show()
        
        if change_result is None:
            print("❌ Cancelled.")
            return
        
        if manager.manager.change_master_password(
            change_result['password'],
            change_result['new_password']
        ):
            print("✅ Master password changed successfully!")
        else:
            print("❌ Failed to change master password.")
        return
    
    # Handle --legacy mode
    if args.legacy:
        print("\nℹ️ Using legacy credential storage (OS Keyring)")
        
        if args.reset:
            print("🔄 Reset mode enabled. Deleting stored credentials...")
            delete_credentials_legacy()
        
        credentials = get_stored_credentials_legacy()
        
        if credentials is None:
            print("📝 Opening credential input dialog...")
            dialog = CredentialDialog(reset_mode=args.reset)
            result = dialog.show()
            
            if result is None:
                print("\n❌ Operation cancelled by user.")
                return
            
            username, password = result
            
            print("\n📝 Saving credentials...")
            if not save_credentials_legacy(username, password):
                print("⚠️ Warning: Could not save credentials.")
            
            credentials = (username, password)
        
        username, password = credentials
        success = await perform_login(username, password, 
                                       headless=args.headless, 
                                       minimize=args.minimize)
        
        if not success:
            print("\n⚠️ Login was not successful.")
            print("   Try running with --reset flag to update credentials:")
            print("   python lpu_auto_login.py --legacy --reset")
        return
    
    # Enhanced mode with multi-profile support
    credentials = handle_credential_workflow(
        reset_mode=args.reset or args.add_profile,
        profile=args.profile
    )
    
    if credentials is None:
        print("\n❌ Operation cancelled or no credentials available.")
        return
    
    username, password = credentials
    success = await perform_login(username, password, 
                                   headless=args.headless, 
                                   minimize=args.minimize)
    
    if not success:
        print("\n⚠️ Login was not successful.")
        print("   Try running with --reset flag to update credentials:")
        print("   python lpu_auto_login.py --reset")


def run():
    """Entry point that handles the async event loop."""
    asyncio.run(main())


# ============================================================================
# BACKWARD COMPATIBILITY FUNCTIONS
# ============================================================================

# Alias functions for backward compatibility with old code
def get_stored_credentials() -> Optional[Tuple[str, str]]:
    """Backward compatible wrapper - uses enhanced or legacy mode."""
    if ENHANCED_SECURITY:
        manager = EnhancedCredentialManager()
        if manager.is_initialized():
            # Can't auto-unlock, return None to trigger workflow
            return None
        return get_stored_credentials_legacy()
    return get_stored_credentials_legacy()


def save_credentials(username: str, password: str) -> bool:
    """Backward compatible wrapper - uses legacy mode."""
    return save_credentials_legacy(username, password)


def delete_credentials() -> bool:
    """Backward compatible wrapper - uses legacy mode."""
    return delete_credentials_legacy()


if __name__ == "__main__":
    run()
