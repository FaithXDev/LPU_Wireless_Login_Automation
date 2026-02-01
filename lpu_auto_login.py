"""
LPU Wireless Auto-Login Script
==============================
This script automates the login process for LPU's 24online wireless network.

Features:
- Secure credential storage using keyring (OS credential manager)
- Simple Tkinter GUI for first-time credential input
- Browser automation using Playwright
- Async/await syntax for non-blocking operations
- Comprehensive error handling

Author: Generated for LPU Wireless Login Automation
"""

import asyncio
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Tuple
import keyring
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout


LOGIN_URL = "https://internet.lpu.in/24online/webpages/client.jsp"

KEYRING_SERVICE = "LPU_Wireless_24Online"
KEYRING_USERNAME_KEY = "username"

PAGE_LOAD_TIMEOUT = 15000   
ELEMENT_TIMEOUT = 5000      
LOGIN_SUCCESS_TIMEOUT = 5000   

FAST_SELECTOR_TIMEOUT = 1500  

def get_stored_credentials() -> Optional[Tuple[str, str]]:
    """
    Retrieve stored credentials from the OS keyring.
    
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


def save_credentials(username: str, password: str) -> bool:
    """
    Securely save credentials to the OS keyring.
    
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


def delete_credentials() -> bool:
    """
    Delete stored credentials from the OS keyring.
    
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
        self.root.resizable(False, False)
        
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


async def perform_login(username: str, password: str) -> bool:
    """
    Perform the automated login using Playwright.
    
    This function:
    1. Opens a Chromium browser (visible, non-headless)
    2. Navigates to the login page
    3. Fills in username and password
    4. Accepts terms and conditions
    5. Submits the login form
    6. Waits for login success
    
    Args:
        username: The login username
        password: The login password
    
    Returns:
        True if login was successful, False otherwise.
    """
    
    print("\n" + "="*60)
    print("🌐 STARTING BROWSER AUTOMATION")
    print("="*60 + "\n")
    
    async with async_playwright() as p:
        print("📌 Launching Chromium browser...")
        browser = await p.chromium.launch(
            headless=False,  
            slow_mo=0        
        )
        
        context = await browser.new_context(
            viewport={'width': 1280, 'height': 720},
            ignore_https_errors=True
        )
        
        page = await context.new_page()
        
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
                    element = await page.wait_for_selector(indicator, timeout=800)  # OPTIMIZED: reduced from 2000ms
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
                print("\n📝 Important Notes:")
                print("   - Keep this browser window open to stay connected")
                print("   - Logout before moving to a new location")
                print("   - To check usage, visit: https://172.20.0.66/myaccount.html")
                print("")
                
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
            await context.close()
            await browser.close()
            print("\n📌 Browser closed.")


async def main():
    """
    Main program entry point.
    
    Program flow:
    1. Check for existing credentials
    2. If not found, show GUI to collect credentials
    3. Save credentials securely
    4. Perform automated login
    """
    
    print("\n" + "="*60)
    print("🔐 LPU WIRELESS AUTO-LOGIN")
    print("="*60 + "\n")
    
    reset_mode = '--reset' in sys.argv or '-r' in sys.argv
    
    if reset_mode:
        print("🔄 Reset mode enabled. Deleting stored credentials...")
        delete_credentials()
        print("")
    
    credentials = get_stored_credentials()
    
    if credentials is None:
        print("📝 Opening credential input dialog...")
        dialog = CredentialDialog(reset_mode=reset_mode)
        result = dialog.show()
        
        if result is None:
            print("\n❌ Operation cancelled by user.")
            return
        
        username, password = result
        
        print("\n📝 Saving credentials...")
        if not save_credentials(username, password):
            print("⚠️ Warning: Could not save credentials. You'll need to enter them again next time.")
        
        credentials = (username, password)
    
    username, password = credentials
    success = await perform_login(username, password)
    
    if not success:
        print("\n⚠️ Login was not successful.")
        print("   Try running with --reset flag to update credentials:")
        print("   python lpu_auto_login.py --reset")


def run():
    """Entry point that handles the async event loop."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
