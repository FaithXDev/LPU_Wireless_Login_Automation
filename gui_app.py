"""
Integrated GUI Application for LPU Wireless Auto-Login
=======================================================

A single-window multi-page application with proper navigation between:
- Master password setup/unlock
- Profile list and selection
- Add/Edit profile (with back and save)
- Security information
- Settings

Features:
- Smooth page transitions
- Back/Save navigation for editors
- Persistent state between pages
- Modern dark theme
- Responsive design

Author: Enhanced UI for LPU Wireless Login Automation
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Callable, Dict, Any
from dataclasses import dataclass
import re


# ============================================================================
# COLOR SCHEME AND STYLES
# ============================================================================

class Theme:
    """Modern dark theme color palette."""
    BG_PRIMARY = "#0f0f1a"
    BG_SECONDARY = "#1a1a2e"
    BG_TERTIARY = "#16213e"
    BG_INPUT = "#0d1b2a"
    
    ACCENT_PRIMARY = "#00d9ff"
    ACCENT_SECONDARY = "#00b4d8"
    ACCENT_SUCCESS = "#00f5a0"
    ACCENT_WARNING = "#ffc107"
    ACCENT_DANGER = "#ff4757"
    
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#a0a0a0"
    TEXT_MUTED = "#6c6c8a"
    
    BORDER_NORMAL = "#2a2a4a"
    BORDER_FOCUS = "#00d9ff"
    
    STRENGTH_WEAK = "#ff4757"
    STRENGTH_FAIR = "#ffc107"
    STRENGTH_GOOD = "#00b4d8"
    STRENGTH_STRONG = "#00f5a0"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ProfileData:
    """Profile information."""
    name: str
    username: str
    password: str = ""
    is_default: bool = False
    last_used: Optional[str] = None


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_password_strength(password: str) -> tuple:
    """Calculate password strength score."""
    if not password:
        return 0, "Empty", Theme.STRENGTH_WEAK
    
    score = 0
    length = len(password)
    
    if length >= 8: score += 20
    if length >= 12: score += 15
    if length >= 16: score += 10
    if re.search(r'[a-z]', password): score += 15
    if re.search(r'[A-Z]', password): score += 15
    if re.search(r'[0-9]', password): score += 15
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 20
    if re.search(r'(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])', password): score += 10
    
    for pattern in ['123', 'abc', 'password', 'qwerty', '111']:
        if pattern.lower() in password.lower():
            score -= 20
    
    score = max(0, min(100, score))
    
    if score < 30: return score, "Weak", Theme.STRENGTH_WEAK
    elif score < 50: return score, "Fair", Theme.STRENGTH_FAIR
    elif score < 75: return score, "Good", Theme.STRENGTH_GOOD
    else: return score, "Strong", Theme.STRENGTH_STRONG


# ============================================================================
# MAIN APPLICATION CLASS
# ============================================================================

class CredentialManagerApp:
    """
    Main application window with multi-page navigation.
    
    Pages:
    - unlock: Master password entry
    - setup: Initial master password setup
    - profiles: Profile list and management
    - add_profile: Add new profile
    - edit_profile: Edit existing profile
    - security: Security information
    """
    
    def __init__(self, credential_manager=None):
        """
        Initialize the application.
        
        Args:
            credential_manager: The SecureCredentialManager instance
        """
        self.credential_manager = credential_manager
        self.result: Optional[Dict[str, Any]] = None
        self.cancelled: bool = False
        
        # Navigation history
        self.page_history: List[str] = []
        self.current_page: str = ""
        
        # Profile data
        self.profiles: List[ProfileData] = []
        self.editing_profile: Optional[ProfileData] = None
        self.selected_profile: Optional[str] = None
        
        # Create main window
        self.root = tk.Tk()
        self._setup_window()
        
        # Container for pages
        self.container = tk.Frame(self.root, bg=Theme.BG_PRIMARY)
        self.container.pack(fill=tk.BOTH, expand=True)
        
        # Page frames dictionary
        self.pages: Dict[str, tk.Frame] = {}
        
        # Initialize pages
        self._create_all_pages()
    
    def _setup_window(self):
        """Configure the main window."""
        self.root.title("🔐 LPU Wireless - Credential Manager")
        self.root.resizable(True, True)
        self.root.configure(bg=Theme.BG_PRIMARY)
        
        # Window size
        width, height = 500, 550
        min_width, min_height = 400, 450
        
        self.root.minsize(min_width, min_height)
        
        # Center window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _create_all_pages(self):
        """Create all page frames."""
        pages_config = [
            ("unlock", self._create_unlock_page),
            ("setup", self._create_setup_page),
            ("profiles", self._create_profiles_page),
            ("add_profile", self._create_add_profile_page),
            ("edit_profile", self._create_edit_profile_page),
            ("security", self._create_security_page),
        ]
        
        for name, create_func in pages_config:
            frame = tk.Frame(self.container, bg=Theme.BG_PRIMARY)
            create_func(frame)
            self.pages[name] = frame
    
    def show_page(self, page_name: str, add_to_history: bool = True):
        """
        Navigate to a page.
        
        Args:
            page_name: Name of the page to show
            add_to_history: Whether to add to navigation history
        """
        # Hide current page
        if self.current_page and self.current_page in self.pages:
            self.pages[self.current_page].pack_forget()
        
        # Add to history
        if add_to_history and self.current_page:
            self.page_history.append(self.current_page)
        
        # Show new page
        self.current_page = page_name
        self.pages[page_name].pack(fill=tk.BOTH, expand=True)
        
        # Refresh page data if needed
        if page_name == "profiles":
            self._refresh_profiles_list()
        elif page_name == "edit_profile":
            self._populate_edit_fields()
    
    def go_back(self):
        """Navigate to previous page."""
        if self.page_history:
            previous = self.page_history.pop()
            self.show_page(previous, add_to_history=False)
        else:
            self.show_page("profiles", add_to_history=False)
    
    # ========================================================================
    # UNLOCK PAGE
    # ========================================================================
    
    def _create_unlock_page(self, parent):
        """Create the unlock page."""
        main_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY, padx=40, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self._create_header(main_frame, "🔓 Unlock Credentials", 
                           "Enter your master password")
        
        # Password field
        password_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        password_frame.pack(fill=tk.X, pady=(30, 20))
        
        tk.Label(password_frame, text="Master Password:", font=('Segoe UI', 10),
                fg=Theme.TEXT_PRIMARY, bg=Theme.BG_PRIMARY).pack(anchor=tk.W)
        
        self.unlock_password_entry = self._create_entry(password_frame, show='•')
        self.unlock_password_entry.bind('<Return>', lambda e: self._on_unlock())
        
        # Buttons
        btn_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        btn_frame.pack(fill=tk.X, pady=(20, 0))
        
        self._create_button(btn_frame, "Cancel", self._on_close, 
                           side=tk.LEFT, style="secondary")
        self._create_button(btn_frame, "Unlock", self._on_unlock, 
                           side=tk.RIGHT, style="primary")
        
        # Security note
        self._create_info_box(main_frame, 
            "🔒 Your password is never stored. Only a secure hash is kept for verification.")
    
    def _on_unlock(self):
        """Handle unlock."""
        password = self.unlock_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter your master password.")
            return
        
        if self.credential_manager:
            if self.credential_manager.unlock(password):
                self.show_page("profiles")
            else:
                messagebox.showerror("Error", "Incorrect password.")
                self.unlock_password_entry.delete(0, tk.END)
        else:
            # Demo mode
            self.show_page("profiles")
    
    # ========================================================================
    # SETUP PAGE
    # ========================================================================
    
    def _create_setup_page(self, parent):
        """Create the initial setup page."""
        main_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY, padx=40, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self._create_header(main_frame, "🔐 Create Master Password",
                           "This password protects all your credentials")
        
        # Password field with strength
        pw_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        pw_frame.pack(fill=tk.X, pady=(25, 0))
        
        tk.Label(pw_frame, text="Master Password:", font=('Segoe UI', 10),
                fg=Theme.TEXT_PRIMARY, bg=Theme.BG_PRIMARY).pack(anchor=tk.W)
        
        self.setup_password_entry = self._create_entry(pw_frame, show='•')
        self.setup_password_entry.bind('<KeyRelease>', self._update_setup_strength)
        
        # Strength meter
        strength_frame = tk.Frame(pw_frame, bg=Theme.BG_PRIMARY)
        strength_frame.pack(fill=tk.X, pady=(8, 0))
        
        self.setup_strength_bg = tk.Frame(strength_frame, bg=Theme.BG_TERTIARY, height=4)
        self.setup_strength_bg.pack(fill=tk.X)
        
        self.setup_strength_bar = tk.Frame(self.setup_strength_bg, 
                                           bg=Theme.STRENGTH_WEAK, height=4, width=0)
        self.setup_strength_bar.place(x=0, y=0, height=4)
        
        self.setup_strength_label = tk.Label(strength_frame, 
            text="Password strength: Enter a password",
            font=('Segoe UI', 8), fg=Theme.TEXT_MUTED, bg=Theme.BG_PRIMARY)
        self.setup_strength_label.pack(anchor=tk.W, pady=(3, 0))
        
        # Confirm password
        confirm_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        confirm_frame.pack(fill=tk.X, pady=(15, 0))
        
        tk.Label(confirm_frame, text="Confirm Password:", font=('Segoe UI', 10),
                fg=Theme.TEXT_PRIMARY, bg=Theme.BG_PRIMARY).pack(anchor=tk.W)
        
        self.setup_confirm_entry = self._create_entry(confirm_frame, show='•')
        
        # Biometric option
        bio_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        bio_frame.pack(fill=tk.X, pady=(15, 0))
        
        self.setup_biometric_var = tk.BooleanVar(value=False)
        tk.Checkbutton(bio_frame, text="Enable Windows Hello (biometric unlock)",
                      variable=self.setup_biometric_var, font=('Segoe UI', 10),
                      fg=Theme.TEXT_SECONDARY, bg=Theme.BG_PRIMARY,
                      selectcolor=Theme.BG_TERTIARY).pack(anchor=tk.W)
        
        # Buttons
        btn_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        btn_frame.pack(fill=tk.X, pady=(25, 0))
        
        self._create_button(btn_frame, "Cancel", self._on_close, 
                           side=tk.LEFT, style="secondary")
        self._create_button(btn_frame, "Create & Continue", self._on_setup_complete, 
                           side=tk.RIGHT, style="primary")
    
    def _update_setup_strength(self, event=None):
        """Update password strength indicator."""
        password = self.setup_password_entry.get()
        score, label, color = calculate_password_strength(password)
        
        bar_width = int((score / 100) * 400)
        self.setup_strength_bar.configure(bg=color)
        self.setup_strength_bar.place(width=bar_width)
        
        self.setup_strength_label.configure(
            text=f"Password strength: {label} ({score}%)", fg=color)
    
    def _on_setup_complete(self):
        """Handle setup completion."""
        password = self.setup_password_entry.get()
        confirm = self.setup_confirm_entry.get()
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters.")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            self.setup_confirm_entry.delete(0, tk.END)
            return
        
        if self.credential_manager:
            enable_bio = self.setup_biometric_var.get()
            if self.credential_manager.initialize(password, enable_bio):
                self.show_page("profiles")
            else:
                messagebox.showerror("Error", "Failed to initialize credential manager.")
        else:
            self.show_page("profiles")
    
    # ========================================================================
    # PROFILES PAGE
    # ========================================================================
    
    def _create_profiles_page(self, parent):
        """Create the profiles list page."""
        main_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY, padx=30, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with title and add button
        header_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        header_frame.pack(fill=tk.X)
        
        tk.Label(header_frame, text="👤 Your Profiles", font=('Segoe UI', 18, 'bold'),
                fg=Theme.ACCENT_PRIMARY, bg=Theme.BG_PRIMARY).pack(side=tk.LEFT)
        
        add_btn = tk.Button(header_frame, text="➕ Add Profile", font=('Segoe UI', 10),
                           bg=Theme.ACCENT_SUCCESS, fg=Theme.BG_PRIMARY,
                           activebackground=Theme.ACCENT_PRIMARY, relief=tk.FLAT,
                           cursor='hand2', command=self._on_add_profile)
        add_btn.pack(side=tk.RIGHT)
        
        tk.Label(main_frame, text="Select a profile or add a new one",
                font=('Segoe UI', 10), fg=Theme.TEXT_SECONDARY,
                bg=Theme.BG_PRIMARY).pack(anchor=tk.W, pady=(5, 15))
        
        # Profile list container
        list_container = tk.Frame(main_frame, bg=Theme.BG_SECONDARY, 
                                 highlightthickness=1, highlightbackground=Theme.BORDER_NORMAL)
        list_container.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Scrollable canvas
        canvas = tk.Canvas(list_container, bg=Theme.BG_SECONDARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=canvas.yview)
        
        self.profiles_list_frame = tk.Frame(canvas, bg=Theme.BG_SECONDARY)
        self.profiles_list_frame.bind("<Configure>", 
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=self.profiles_list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.profiles_canvas = canvas
        self.profiles_selected_var = tk.StringVar()
        
        # Action buttons
        action_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        action_frame.pack(fill=tk.X, pady=(0, 15))
        
        actions = [
            ("✏️ Edit", self._on_edit_profile),
            ("⭐ Set Default", self._on_set_default),
            ("🗑️ Delete", self._on_delete_profile),
            ("🔒 Security", self._on_show_security),
        ]
        
        for text, cmd in actions:
            tk.Button(action_frame, text=text, font=('Segoe UI', 9),
                     bg=Theme.BG_TERTIARY, fg=Theme.TEXT_PRIMARY,
                     activebackground=Theme.BORDER_NORMAL, relief=tk.FLAT,
                     cursor='hand2', command=cmd, padx=10).pack(side=tk.LEFT, padx=(0, 8))
        
        # Main action buttons
        bottom_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        bottom_frame.pack(fill=tk.X)
        
        self._create_button(bottom_frame, "Close", self._on_close, 
                           side=tk.LEFT, style="secondary")
        self._create_button(bottom_frame, "Use Selected Profile", self._on_use_profile, 
                           side=tk.RIGHT, style="primary")
    
    def _refresh_profiles_list(self):
        """Refresh the profiles list display."""
        # Clear existing items
        for widget in self.profiles_list_frame.winfo_children():
            widget.destroy()
        
        # Always reload profiles from manager
        if self.credential_manager:
            try:
                # Check if manager has list_profiles method
                if hasattr(self.credential_manager, 'list_profiles'):
                    profiles = self.credential_manager.list_profiles()
                    self.profiles = [ProfileData(
                        name=p.name, username=p.username, 
                        is_default=p.is_default, 
                        last_used=getattr(p, 'last_used', None)
                    ) for p in profiles]
                elif hasattr(self.credential_manager, 'get_all_profiles'):
                    profiles = self.credential_manager.get_all_profiles()
                    self.profiles = [ProfileData(
                        name=p['name'], username=p['username'], 
                        is_default=p.get('is_default', False), 
                        last_used=p.get('last_used', None)
                    ) for p in profiles]
            except Exception as e:
                print(f"Error loading profiles: {e}")
                # Keep existing self.profiles if load fails
        
        # Debug: print profiles count
        print(f"📋 Loaded {len(self.profiles)} profiles")
        
        if not self.profiles:
            tk.Label(self.profiles_list_frame,
                    text="No profiles found.\nClick '➕ Add Profile' to create one.",
                    font=('Segoe UI', 11), fg=Theme.TEXT_MUTED,
                    bg=Theme.BG_SECONDARY, pady=40).pack()
            return
        
        # Set first or default profile as selected
        default_profile = next((p for p in self.profiles if p.is_default), None)
        if default_profile:
            self.profiles_selected_var.set(default_profile.name)
        elif self.profiles:
            self.profiles_selected_var.set(self.profiles[0].name)
        
        # Create profile items
        for profile in self.profiles:
            self._create_profile_item(self.profiles_list_frame, profile)
        
        # Update canvas scroll region
        self.profiles_list_frame.update_idletasks()
        self.profiles_canvas.configure(scrollregion=self.profiles_canvas.bbox("all"))
    
    def _create_profile_item(self, parent, profile: ProfileData):
        """Create a single profile item."""
        frame = tk.Frame(parent, bg=Theme.BG_SECONDARY, padx=15, pady=12)
        frame.pack(fill=tk.X)
        
        # Make entire frame clickable
        def select_profile():
            self.profiles_selected_var.set(profile.name)
        
        frame.bind('<Button-1>', lambda e: select_profile())
        
        # Radio button
        radio = tk.Radiobutton(frame, variable=self.profiles_selected_var,
                              value=profile.name, bg=Theme.BG_SECONDARY,
                              activebackground=Theme.BG_SECONDARY,
                              selectcolor=Theme.ACCENT_PRIMARY)
        radio.pack(side=tk.LEFT)
        
        # Info section
        info_frame = tk.Frame(frame, bg=Theme.BG_SECONDARY)
        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        info_frame.bind('<Button-1>', lambda e: select_profile())
        
        name_text = f"{profile.name} ⭐" if profile.is_default else profile.name
        name_lbl = tk.Label(info_frame, text=name_text, font=('Segoe UI', 11, 'bold'),
                           fg=Theme.TEXT_PRIMARY, bg=Theme.BG_SECONDARY, anchor='w')
        name_lbl.pack(fill=tk.X)
        name_lbl.bind('<Button-1>', lambda e: select_profile())
        
        user_lbl = tk.Label(info_frame, text=f"Username: {profile.username}",
                           font=('Segoe UI', 9), fg=Theme.TEXT_SECONDARY,
                           bg=Theme.BG_SECONDARY, anchor='w')
        user_lbl.pack(fill=tk.X)
        user_lbl.bind('<Button-1>', lambda e: select_profile())
        
        if profile.last_used:
            last_lbl = tk.Label(info_frame, text=f"Last used: {profile.last_used[:16]}",
                              font=('Segoe UI', 8), fg=Theme.TEXT_MUTED,
                              bg=Theme.BG_SECONDARY, anchor='w')
            last_lbl.pack(fill=tk.X)
            last_lbl.bind('<Button-1>', lambda e: select_profile())
        
        # Separator
        tk.Frame(parent, bg=Theme.BORDER_NORMAL, height=1).pack(fill=tk.X)
    
    def _on_add_profile(self):
        """Navigate to add profile page."""
        self.editing_profile = None
        self._clear_profile_form()
        self.show_page("add_profile")
    
    def _on_edit_profile(self):
        """Navigate to edit profile page."""
        selected = self.profiles_selected_var.get()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a profile to edit.")
            return
        
        profile = next((p for p in self.profiles if p.name == selected), None)
        if profile:
            self.editing_profile = profile
            self.show_page("edit_profile")
    
    def _on_set_default(self):
        """Set selected profile as default."""
        selected = self.profiles_selected_var.get()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a profile.")
            return
        
        if self.credential_manager:
            try:
                self.credential_manager.set_default_profile(selected)
                messagebox.showinfo("Success", f"'{selected}' is now the default profile.")
                self._refresh_profiles_list()
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def _on_delete_profile(self):
        """Delete selected profile."""
        selected = self.profiles_selected_var.get()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a profile to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Are you sure you want to delete '{selected}'?\n"
                              "This cannot be undone."):
            if self.credential_manager:
                try:
                    self.credential_manager.delete_profile(selected)
                    self._refresh_profiles_list()
                except Exception as e:
                    messagebox.showerror("Error", str(e))
    
    def _on_show_security(self):
        """Navigate to security info page."""
        self.show_page("security")
    
    def _on_use_profile(self):
        """Use selected profile and close."""
        selected = self.profiles_selected_var.get()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a profile.")
            return
        
        self.result = {"action": "login", "profile": selected}
        self.root.destroy()
    
    # ========================================================================
    # ADD PROFILE PAGE
    # ========================================================================
    
    def _create_add_profile_page(self, parent):
        """Create the add profile page."""
        main_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY, padx=40, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with back button
        header = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        header.pack(fill=tk.X)
        
        back_btn = tk.Button(header, text="← Back", font=('Segoe UI', 10),
                            bg=Theme.BG_TERTIARY, fg=Theme.TEXT_PRIMARY,
                            relief=tk.FLAT, cursor='hand2',
                            command=lambda: self.show_page("profiles"))
        back_btn.pack(side=tk.LEFT)
        
        tk.Label(header, text="➕ Add New Profile", font=('Segoe UI', 18, 'bold'),
                fg=Theme.ACCENT_PRIMARY, bg=Theme.BG_PRIMARY).pack(side=tk.LEFT, padx=(15, 0))
        
        tk.Label(main_frame, text="Create a new credential profile",
                font=('Segoe UI', 10), fg=Theme.TEXT_SECONDARY,
                bg=Theme.BG_PRIMARY).pack(anchor=tk.W, pady=(10, 20))
        
        # Form fields
        self._create_profile_form(main_frame, "add")
        
        # Buttons
        btn_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        btn_frame.pack(fill=tk.X, pady=(25, 0))
        
        self._create_button(btn_frame, "← Back to Profiles", 
                           lambda: self.show_page("profiles"), 
                           side=tk.LEFT, style="secondary")
        self._create_button(btn_frame, "Save Profile", self._on_save_new_profile, 
                           side=tk.RIGHT, style="primary")
    
    def _on_save_new_profile(self):
        """Save new profile and return to profiles page."""
        name = self.add_name_entry.get().strip()
        username = self.add_username_entry.get().strip()
        password = self.add_password_entry.get()
        is_default = self.add_default_var.get()
        
        if not name or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return
        
        if self.credential_manager:
            try:
                self.credential_manager.add_profile(name, username, password, is_default)
                messagebox.showinfo("Success", f"Profile '{name}' created successfully!")
                self._clear_profile_form()
                self.show_page("profiles")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            # Demo mode
            self.profiles.append(ProfileData(name, username, password, is_default))
            messagebox.showinfo("Success", f"Profile '{name}' created!")
            self._clear_profile_form()
            self.show_page("profiles")
    
    # ========================================================================
    # EDIT PROFILE PAGE
    # ========================================================================
    
    def _create_edit_profile_page(self, parent):
        """Create the edit profile page."""
        main_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY, padx=40, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with back button
        header = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        header.pack(fill=tk.X)
        
        back_btn = tk.Button(header, text="← Back", font=('Segoe UI', 10),
                            bg=Theme.BG_TERTIARY, fg=Theme.TEXT_PRIMARY,
                            relief=tk.FLAT, cursor='hand2',
                            command=lambda: self.show_page("profiles"))
        back_btn.pack(side=tk.LEFT)
        
        self.edit_title_label = tk.Label(header, text="✏️ Edit Profile", 
                                         font=('Segoe UI', 18, 'bold'),
                                         fg=Theme.ACCENT_PRIMARY, bg=Theme.BG_PRIMARY)
        self.edit_title_label.pack(side=tk.LEFT, padx=(15, 0))
        
        tk.Label(main_frame, text="Modify profile details",
                font=('Segoe UI', 10), fg=Theme.TEXT_SECONDARY,
                bg=Theme.BG_PRIMARY).pack(anchor=tk.W, pady=(10, 20))
        
        # Form fields
        self._create_profile_form(main_frame, "edit")
        
        # Buttons - Back and Save
        btn_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        btn_frame.pack(fill=tk.X, pady=(25, 0))
        
        self._create_button(btn_frame, "← Back (Discard)", 
                           lambda: self.show_page("profiles"), 
                           side=tk.LEFT, style="secondary")
        self._create_button(btn_frame, "Save Changes", self._on_save_edit_profile, 
                           side=tk.RIGHT, style="primary")
    
    def _populate_edit_fields(self):
        """Populate edit form with current profile data."""
        if not self.editing_profile:
            return
        
        profile = self.editing_profile
        
        self.edit_title_label.configure(text=f"✏️ Edit: {profile.name}")
        
        self.edit_name_entry.delete(0, tk.END)
        self.edit_name_entry.insert(0, profile.name)
        
        self.edit_username_entry.delete(0, tk.END)
        self.edit_username_entry.insert(0, profile.username)
        
        self.edit_password_entry.delete(0, tk.END)
        # Don't show actual password for security
        
        self.edit_default_var.set(profile.is_default)
    
    def _on_save_edit_profile(self):
        """Save edited profile and return to profiles page."""
        if not self.editing_profile:
            return
        
        old_name = self.editing_profile.name
        new_name = self.edit_name_entry.get().strip()
        username = self.edit_username_entry.get().strip()
        password = self.edit_password_entry.get()  # Optional for edit
        is_default = self.edit_default_var.get()
        
        if not new_name or not username:
            messagebox.showerror("Error", "Profile name and username are required.")
            return
        
        if self.credential_manager:
            try:
                # Update profile
                self.credential_manager.update_profile(
                    old_name, new_name, username, 
                    password if password else None,
                    is_default
                )
                messagebox.showinfo("Success", "Profile updated successfully!")
                self.show_page("profiles")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            # Demo mode - update in local list
            for i, p in enumerate(self.profiles):
                if p.name == old_name:
                    self.profiles[i] = ProfileData(
                        name=new_name, 
                        username=username,
                        password=password if password else p.password,
                        is_default=is_default,
                        last_used=p.last_used
                    )
                    break
            messagebox.showinfo("Success", "Profile updated!")
            self.show_page("profiles")
    
    def _create_profile_form(self, parent, prefix: str):
        """Create profile form fields."""
        # Profile name
        name_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        name_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(name_frame, text="Profile Name:", font=('Segoe UI', 10),
                fg=Theme.TEXT_PRIMARY, bg=Theme.BG_PRIMARY).pack(anchor=tk.W)
        
        name_entry = self._create_entry(name_frame)
        setattr(self, f"{prefix}_name_entry", name_entry)
        
        # Username
        user_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        user_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(user_frame, text="Username:", font=('Segoe UI', 10),
                fg=Theme.TEXT_PRIMARY, bg=Theme.BG_PRIMARY).pack(anchor=tk.W)
        
        user_entry = self._create_entry(user_frame)
        setattr(self, f"{prefix}_username_entry", user_entry)
        
        # Password
        pw_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        pw_frame.pack(fill=tk.X, pady=(0, 15))
        
        pw_label = "Password:" if prefix == "add" else "New Password (leave blank to keep current):"
        tk.Label(pw_frame, text=pw_label, font=('Segoe UI', 10),
                fg=Theme.TEXT_PRIMARY, bg=Theme.BG_PRIMARY).pack(anchor=tk.W)
        
        pw_entry = self._create_entry(pw_frame, show='•')
        setattr(self, f"{prefix}_password_entry", pw_entry)
        
        # Default checkbox
        default_var = tk.BooleanVar(value=False)
        setattr(self, f"{prefix}_default_var", default_var)
        
        tk.Checkbutton(parent, text="Set as default profile", variable=default_var,
                      font=('Segoe UI', 10), fg=Theme.TEXT_SECONDARY,
                      bg=Theme.BG_PRIMARY, selectcolor=Theme.BG_TERTIARY).pack(anchor=tk.W)
    
    def _clear_profile_form(self):
        """Clear the add profile form."""
        if hasattr(self, 'add_name_entry'):
            self.add_name_entry.delete(0, tk.END)
        if hasattr(self, 'add_username_entry'):
            self.add_username_entry.delete(0, tk.END)
        if hasattr(self, 'add_password_entry'):
            self.add_password_entry.delete(0, tk.END)
        if hasattr(self, 'add_default_var'):
            self.add_default_var.set(False)
    
    # ========================================================================
    # SECURITY PAGE
    # ========================================================================
    
    def _create_security_page(self, parent):
        """Create the security information page."""
        main_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY, padx=40, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with back button
        header = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        header.pack(fill=tk.X)
        
        back_btn = tk.Button(header, text="← Back", font=('Segoe UI', 10),
                            bg=Theme.BG_TERTIARY, fg=Theme.TEXT_PRIMARY,
                            relief=tk.FLAT, cursor='hand2',
                            command=lambda: self.show_page("profiles"))
        back_btn.pack(side=tk.LEFT)
        
        tk.Label(header, text="🔒 Security Information", font=('Segoe UI', 18, 'bold'),
                fg=Theme.ACCENT_PRIMARY, bg=Theme.BG_PRIMARY).pack(side=tk.LEFT, padx=(15, 0))
        
        # Security info cards
        info_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        
        security_items = [
            ("🔐 Encryption", "AES-256 (Fernet) with PBKDF2-HMAC-SHA256"),
            ("🔑 Key Derivation", "480,000 iterations (OWASP recommended)"),
            ("📁 Storage", "Local encrypted SQLite database"),
            ("🔒 Master Password", "Never stored - only secure hash kept"),
            ("🖐️ Biometrics", "Windows Hello support (optional)"),
        ]
        
        for icon_title, value in security_items:
            card = tk.Frame(info_frame, bg=Theme.BG_SECONDARY, padx=15, pady=12)
            card.pack(fill=tk.X, pady=(0, 10))
            
            tk.Label(card, text=icon_title, font=('Segoe UI', 11, 'bold'),
                    fg=Theme.TEXT_PRIMARY, bg=Theme.BG_SECONDARY).pack(anchor=tk.W)
            tk.Label(card, text=value, font=('Segoe UI', 10),
                    fg=Theme.TEXT_SECONDARY, bg=Theme.BG_SECONDARY).pack(anchor=tk.W)
        
        # Storage location
        if self.credential_manager:
            try:
                path = self.credential_manager.get_database_path()
                loc_card = tk.Frame(info_frame, bg=Theme.BG_TERTIARY, padx=15, pady=12)
                loc_card.pack(fill=tk.X, pady=(10, 0))
                
                tk.Label(loc_card, text="📂 Database Location", font=('Segoe UI', 11, 'bold'),
                        fg=Theme.ACCENT_PRIMARY, bg=Theme.BG_TERTIARY).pack(anchor=tk.W)
                tk.Label(loc_card, text=str(path), font=('Segoe UI', 9),
                        fg=Theme.TEXT_SECONDARY, bg=Theme.BG_TERTIARY,
                        wraplength=380).pack(anchor=tk.W)
            except:
                pass
        
        # Back button
        btn_frame = tk.Frame(main_frame, bg=Theme.BG_PRIMARY)
        btn_frame.pack(fill=tk.X, pady=(20, 0))
        
        self._create_button(btn_frame, "← Back to Profiles", 
                           lambda: self.show_page("profiles"), 
                           side=tk.LEFT, style="secondary")
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _create_header(self, parent, title: str, subtitle: str):
        """Create a page header."""
        tk.Label(parent, text=title, font=('Segoe UI', 18, 'bold'),
                fg=Theme.ACCENT_PRIMARY, bg=Theme.BG_PRIMARY).pack(pady=(0, 5))
        tk.Label(parent, text=subtitle, font=('Segoe UI', 10),
                fg=Theme.TEXT_SECONDARY, bg=Theme.BG_PRIMARY).pack()
    
    def _create_entry(self, parent, show: str = None) -> tk.Entry:
        """Create a styled entry field."""
        entry = tk.Entry(parent, font=('Segoe UI', 11), bg=Theme.BG_INPUT,
                        fg=Theme.TEXT_PRIMARY, insertbackground=Theme.ACCENT_PRIMARY,
                        relief=tk.FLAT, highlightthickness=2,
                        highlightbackground=Theme.BORDER_NORMAL,
                        highlightcolor=Theme.BORDER_FOCUS)
        if show:
            entry.configure(show=show)
        entry.pack(fill=tk.X, pady=(5, 0), ipady=8)
        return entry
    
    def _create_button(self, parent, text: str, command: Callable,
                       side: str = tk.LEFT, style: str = "primary"):
        """Create a styled button."""
        if style == "primary":
            bg, fg = Theme.ACCENT_PRIMARY, Theme.BG_PRIMARY
            active_bg = Theme.ACCENT_SECONDARY
        else:
            bg, fg = Theme.BG_TERTIARY, Theme.TEXT_PRIMARY
            active_bg = Theme.BORDER_NORMAL
        
        btn = tk.Button(parent, text=text, font=('Segoe UI', 10, 'bold' if style == "primary" else 'normal'),
                       bg=bg, fg=fg, activebackground=active_bg,
                       activeforeground=fg, relief=tk.FLAT, cursor='hand2',
                       command=command, padx=20, pady=8)
        btn.pack(side=side)
        return btn
    
    def _create_info_box(self, parent, text: str):
        """Create an info box."""
        box = tk.Frame(parent, bg=Theme.BG_TERTIARY, padx=15, pady=10)
        box.pack(fill=tk.X, pady=(25, 0))
        
        tk.Label(box, text=text, font=('Segoe UI', 9), fg=Theme.TEXT_MUTED,
                bg=Theme.BG_TERTIARY, wraplength=380).pack()
    
    def _on_close(self):
        """Handle window close."""
        self.cancelled = True
        self.root.destroy()
    
    # ========================================================================
    # PUBLIC API
    # ========================================================================
    
    def run(self, start_page: str = "unlock") -> Optional[Dict[str, Any]]:
        """
        Run the application.
        
        Args:
            start_page: Initial page to show ("unlock", "setup", "profiles")
        
        Returns:
            Result dictionary or None if cancelled
        """
        self.show_page(start_page, add_to_history=False)
        self.root.mainloop()
        
        if self.cancelled:
            return None
        return self.result


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def show_credential_manager(credential_manager=None, start_page: str = "profiles"):
    """
    Show the credential manager GUI.
    
    Args:
        credential_manager: The SecureCredentialManager instance
        start_page: Which page to start on
    
    Returns:
        Result dictionary or None if cancelled
    """
    app = CredentialManagerApp(credential_manager)
    return app.run(start_page)


def show_master_password_setup():
    """Show the master password setup dialog."""
    app = CredentialManagerApp()
    return app.run("setup")


def show_profile_selector(profiles: List[ProfileData]):
    """Show profile selection dialog."""
    app = CredentialManagerApp()
    app.profiles = profiles
    return app.run("profiles")


# ============================================================================
# DEMO / TESTING
# ============================================================================

if __name__ == "__main__":
    # Demo with sample data
    app = CredentialManagerApp()
    
    # Add some demo profiles
    app.profiles = [
        ProfileData("Student", "12316501", is_default=True, last_used="2026-02-05 12:00"),
        ProfileData("Guest", "guest123", is_default=False, last_used="2026-02-04 18:30"),
        ProfileData("Staff", "staff456", is_default=False),
    ]
    
    result = app.run("profiles")
    print(f"Result: {result}")
