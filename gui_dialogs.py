"""
Enhanced GUI Components for LPU Wireless Auto-Login
=====================================================

This module provides modern, secure GUI dialogs for:
- Master password entry and setup
- Multi-profile credential management
- Security settings configuration
- Profile selection and switching

Features:
- Modern dark theme with gradients
- Password strength indicator
- Profile management interface
- Security information display
- Biometric toggle option

Author: Enhanced UI for LPU Wireless Login Automation
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Tuple, List, Callable
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
    
    # Password strength colors
    STRENGTH_WEAK = "#ff4757"
    STRENGTH_FAIR = "#ffc107"
    STRENGTH_GOOD = "#00b4d8"
    STRENGTH_STRONG = "#00f5a0"


# ============================================================================
# PASSWORD STRENGTH INDICATOR
# ============================================================================

def calculate_password_strength(password: str) -> Tuple[int, str, str]:
    """
    Calculate password strength score.
    
    Args:
        password: The password to evaluate
    
    Returns:
        Tuple of (score 0-100, strength_label, color)
    """
    if not password:
        return 0, "Empty", Theme.STRENGTH_WEAK
    
    score = 0
    
    length = len(password)
    if length >= 8:
        score += 20
    if length >= 12:
        score += 15
    if length >= 16:
        score += 10
    
    if re.search(r'[a-z]', password):
        score += 15
    if re.search(r'[A-Z]', password):
        score += 15
    if re.search(r'[0-9]', password):
        score += 15
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 20
    
    if re.search(r'(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])', password):
        score += 10
    
    common_patterns = ['123', 'abc', 'password', 'qwerty', '111']
    for pattern in common_patterns:
        if pattern.lower() in password.lower():
            score -= 20
    
    score = max(0, min(100, score))
    
    if score < 30:
        return score, "Weak", Theme.STRENGTH_WEAK
    elif score < 50:
        return score, "Fair", Theme.STRENGTH_FAIR
    elif score < 75:
        return score, "Good", Theme.STRENGTH_GOOD
    else:
        return score, "Strong", Theme.STRENGTH_STRONG


# ============================================================================
# MASTER PASSWORD DIALOG
# ============================================================================

class MasterPasswordDialog:
    """
    Dialog for entering or setting up the master password.
    
    Modes:
    - Setup: First-time setup with confirmation
    - Unlock: Simple password entry for existing setup
    - Change: For changing the master password
    """
    
    def __init__(self, mode: str = "unlock", parent: Optional[tk.Tk] = None):
        """
        Initialize the master password dialog.
        
        Args:
            mode: "setup", "unlock", or "change"
            parent: Optional parent window
        """
        self.mode = mode
        self.password: Optional[str] = None
        self.new_password: Optional[str] = None
        self.enable_biometric: bool = False
        self.cancelled: bool = False
        
        if parent:
            self.root = tk.Toplevel(parent)
        else:
            self.root = tk.Tk()
        
        self._setup_window()
        self._create_widgets()
    
    def _setup_window(self):
        """Configure the dialog window."""
        titles = {
            "setup": "🔐 Setup Master Password",
            "unlock": "🔓 Unlock Credential Manager",
            "change": "🔑 Change Master Password"
        }
        self.root.title(titles.get(self.mode, "Master Password"))
        self.root.resizable(True, True) 
        self.root.configure(bg=Theme.BG_PRIMARY)
        
        if self.mode == "setup":
            width, height = 450, 420
        elif self.mode == "change":
            width, height = 450, 380
        else:
            width, height = 400, 280
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_cancel)
    
    def _create_widgets(self):
        """Create all dialog widgets."""
        main_frame = tk.Frame(self.root, bg=Theme.BG_PRIMARY, padx=35, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        if self.mode == "setup":
            self._create_setup_ui(main_frame)
        elif self.mode == "change":
            self._create_change_ui(main_frame)
        else:
            self._create_unlock_ui(main_frame)
    
    def _create_unlock_ui(self, parent):
        """Create unlock mode UI."""
    
        title = tk.Label(
            parent,
            text="🔓 Unlock Credentials",
            font=('Segoe UI', 18, 'bold'),
            fg=Theme.ACCENT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        title.pack(pady=(0, 10))
        
        subtitle = tk.Label(
            parent,
            text="Enter your master password to access saved credentials",
            font=('Segoe UI', 10),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_PRIMARY
        )
        subtitle.pack(pady=(0, 25))
        
        self._create_password_field(parent, "Master Password:", "password_entry")
        
        
        self._create_buttons(parent, "Unlock")
        
        self._create_security_note(parent)
        
        self.password_entry.focus_set()
        self.root.bind('<Return>', lambda e: self._on_submit())
    
    def _create_setup_ui(self, parent):
        """Create setup mode UI with password strength."""
        title = tk.Label(
            parent,
            text="🔐 Create Master Password",
            font=('Segoe UI', 18, 'bold'),
            fg=Theme.ACCENT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        title.pack(pady=(0, 5))
        
        subtitle = tk.Label(
            parent,
            text="This password protects all your saved credentials",
            font=('Segoe UI', 10),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_PRIMARY
        )
        subtitle.pack(pady=(0, 20))
        
        self._create_password_field(parent, "Master Password:", "password_entry", show_strength=True)
        
        self._create_password_field(parent, "Confirm Password:", "confirm_entry")
        
        self._create_biometric_option(parent)
        
        self._create_buttons(parent, "Create Password")
        
        self.password_entry.focus_set()
        self.root.bind('<Return>', lambda e: self._on_submit())
    
    def _create_change_ui(self, parent):
        """Create change password UI."""
        title = tk.Label(
            parent,
            text="🔑 Change Master Password",
            font=('Segoe UI', 18, 'bold'),
            fg=Theme.ACCENT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        title.pack(pady=(0, 20))
        
        self._create_password_field(parent, "Current Password:", "current_entry")
        
        self._create_password_field(parent, "New Password:", "password_entry", show_strength=True)
        
        self._create_password_field(parent, "Confirm New Password:", "confirm_entry")
        
        self._create_buttons(parent, "Change Password")
        
        self.current_entry.focus_set()
        self.root.bind('<Return>', lambda e: self._on_submit())
    
    def _create_password_field(self, parent, label_text: str, attr_name: str, 
                               show_strength: bool = False):
        """Create a password input field with optional strength meter."""
        frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        frame.pack(fill=tk.X, pady=(0, 15))
        
        label = tk.Label(
            frame,
            text=label_text,
            font=('Segoe UI', 10),
            fg=Theme.TEXT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        label.pack(anchor=tk.W)
        
        entry = tk.Entry(
            frame,
            font=('Segoe UI', 11),
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT_PRIMARY,
            insertbackground=Theme.ACCENT_PRIMARY,
            relief=tk.FLAT,
            highlightthickness=2,
            highlightbackground=Theme.BORDER_NORMAL,
            highlightcolor=Theme.BORDER_FOCUS,
            show='•'
        )
        entry.pack(fill=tk.X, pady=(5, 0), ipady=8)
        setattr(self, attr_name, entry)
        
        if show_strength:
            # Strength meter
            strength_frame = tk.Frame(frame, bg=Theme.BG_PRIMARY)
            strength_frame.pack(fill=tk.X, pady=(8, 0))
            
            strength_bar_bg = tk.Frame(strength_frame, bg=Theme.BG_TERTIARY, height=4)
            strength_bar_bg.pack(fill=tk.X)
            
            self.strength_bar = tk.Frame(strength_bar_bg, bg=Theme.STRENGTH_WEAK, height=4, width=0)
            self.strength_bar.place(x=0, y=0, height=4)
            
            self.strength_label = tk.Label(
                strength_frame,
                text="Password strength: Enter a password",
                font=('Segoe UI', 8),
                fg=Theme.TEXT_MUTED,
                bg=Theme.BG_PRIMARY
            )
            self.strength_label.pack(anchor=tk.W, pady=(3, 0))
            
            entry.bind('<KeyRelease>', self._update_strength)
    
    def _update_strength(self, event=None):
        """Update the password strength indicator."""
        password = self.password_entry.get()
        score, label, color = calculate_password_strength(password)
        
        bar_width = int((score / 100) * 380) 
        self.strength_bar.configure(bg=color)
        self.strength_bar.place(width=bar_width)
        
        self.strength_label.configure(
            text=f"Password strength: {label} ({score}%)",
            fg=color
        )
    
    def _create_biometric_option(self, parent):
        """Create biometric authentication toggle."""
        frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        frame.pack(fill=tk.X, pady=(5, 15))
        
        self.biometric_var = tk.BooleanVar(value=False)
        
        checkbox = tk.Checkbutton(
            frame,
            text="Enable Windows Hello (biometric unlock)",
            variable=self.biometric_var,
            font=('Segoe UI', 10),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_PRIMARY,
            selectcolor=Theme.BG_TERTIARY,
            activebackground=Theme.BG_PRIMARY,
            activeforeground=Theme.TEXT_PRIMARY
        )
        checkbox.pack(anchor=tk.W)
        
        note = tk.Label(
            frame,
            text="Use fingerprint or face recognition to unlock credentials",
            font=('Segoe UI', 8),
            fg=Theme.TEXT_MUTED,
            bg=Theme.BG_PRIMARY
        )
        note.pack(anchor=tk.W, padx=(24, 0))
    
    def _create_buttons(self, parent, submit_text: str):
        """Create action buttons."""
        button_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            font=('Segoe UI', 10),
            bg=Theme.BG_TERTIARY,
            fg=Theme.TEXT_PRIMARY,
            activebackground=Theme.BORDER_NORMAL,
            activeforeground=Theme.TEXT_PRIMARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_cancel,
            width=12
        )
        cancel_btn.pack(side=tk.LEFT)
        
        submit_btn = tk.Button(
            button_frame,
            text=submit_text,
            font=('Segoe UI', 10, 'bold'),
            bg=Theme.ACCENT_PRIMARY,
            fg=Theme.BG_PRIMARY,
            activebackground=Theme.ACCENT_SECONDARY,
            activeforeground=Theme.BG_PRIMARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_submit,
            width=18
        )
        submit_btn.pack(side=tk.RIGHT)
    
    def _create_security_note(self, parent):
        """Create security information note."""
        note_frame = tk.Frame(parent, bg=Theme.BG_TERTIARY, padx=15, pady=10)
        note_frame.pack(fill=tk.X, pady=(20, 0))
        
        note = tk.Label(
            note_frame,
            text="🔒 Your password is never stored. Only a secure hash is kept for verification.",
            font=('Segoe UI', 8),
            fg=Theme.TEXT_MUTED,
            bg=Theme.BG_TERTIARY,
            wraplength=330
        )
        note.pack()
    
    def _on_submit(self):
        """Handle form submission."""
        if self.mode == "unlock":
            password = self.password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter your master password.")
                return
            self.password = password
            
        elif self.mode == "setup":
            password = self.password_entry.get()
            confirm = self.confirm_entry.get()
            
            if len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters long.")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                self.confirm_entry.delete(0, tk.END)
                return
            
            score, _, _ = calculate_password_strength(password)
            if score < 30:
                if not messagebox.askyesno(
                    "Weak Password",
                    "Your password is weak. A stronger password is recommended.\n\n"
                    "Do you want to continue anyway?"
                ):
                    return
            
            self.password = password
            self.enable_biometric = self.biometric_var.get()
            
        elif self.mode == "change":
            current = self.current_entry.get()
            new_password = self.password_entry.get()
            confirm = self.confirm_entry.get()
            
            if not current:
                messagebox.showerror("Error", "Please enter your current password.")
                return
            
            if len(new_password) < 8:
                messagebox.showerror("Error", "New password must be at least 8 characters long.")
                return
            
            if new_password != confirm:
                messagebox.showerror("Error", "New passwords do not match.")
                self.confirm_entry.delete(0, tk.END)
                return
            
            self.password = current
            self.new_password = new_password
        
        self.root.destroy()
    
    def _on_cancel(self):
        """Handle dialog cancellation."""
        self.cancelled = True
        self.root.destroy()
    
    def show(self) -> Optional[dict]:
        """
        Display the dialog and wait for user input.
        
        Returns:
            Dictionary with password data, or None if cancelled.
        """
        self.root.mainloop()
        
        if self.cancelled:
            return None
        
        result = {'password': self.password}
        
        if self.mode == "setup":
            result['enable_biometric'] = self.enable_biometric
        elif self.mode == "change":
            result['new_password'] = self.new_password
        
        return result


# ============================================================================
# PROFILE SELECTION DIALOG
# ============================================================================

@dataclass
class ProfileInfo:
    """Profile information for display."""
    name: str
    username: str
    is_default: bool
    last_used: Optional[str] = None


class ProfileSelectionDialog:
    """
    Dialog for selecting and managing credential profiles.
    
    Features:
    - List all available profiles
    - Add new profiles
    - Edit/delete existing profiles
    - Set default profile
    """
    
    def __init__(self, profiles: List[ProfileInfo], parent: Optional[tk.Tk] = None):
        """
        Initialize the profile selection dialog.
        
        Args:
            profiles: List of available profiles
            parent: Optional parent window
        """
        self.profiles = profiles
        self.selected_profile: Optional[str] = None
        self.action: Optional[str] = None  
        self.cancelled: bool = False
        
        if parent:
            self.root = tk.Toplevel(parent)
        else:
            self.root = tk.Tk()
        
        self._setup_window()
        self._create_widgets()
    
    def _setup_window(self):
        """Configure the dialog window."""
        self.root.title("👤 Select Profile")
        self.root.resizable(True, True) 
        self.root.configure(bg=Theme.BG_PRIMARY)
        
        width, height = 450, 450
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_cancel)
    
    def _create_widgets(self):
        """Create all dialog widgets."""
        main_frame = tk.Frame(self.root, bg=Theme.BG_PRIMARY, padx=25, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        title = tk.Label(
            main_frame,
            text="👤 Select Profile",
            font=('Segoe UI', 18, 'bold'),
            fg=Theme.ACCENT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        title.pack(pady=(0, 5))
        
        subtitle = tk.Label(
            main_frame,
            text="Choose a profile to use for login",
            font=('Segoe UI', 10),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_PRIMARY
        )
        subtitle.pack(pady=(0, 20))
        
        self._create_profile_list(main_frame)
        
        self._create_action_buttons(main_frame)
        
        self._create_main_buttons(main_frame)
    
    def _create_profile_list(self, parent):
        """Create the scrollable profile list."""
        list_frame = tk.Frame(parent, bg=Theme.BG_SECONDARY, highlightthickness=1,
                             highlightbackground=Theme.BORDER_NORMAL)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        canvas = tk.Canvas(list_frame, bg=Theme.BG_SECONDARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=Theme.BG_SECONDARY)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=396)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        self.selected_var = tk.StringVar()
        
        if self.profiles:
            for profile in self.profiles:
                self._create_profile_item(scrollable_frame, profile)
            
            # Select first profile by default
            self.selected_var.set(self.profiles[0].name)
        else:
            no_profiles = tk.Label(
                scrollable_frame,
                text="No profiles found.\nClick 'Add Profile' to create one.",
                font=('Segoe UI', 11),
                fg=Theme.TEXT_MUTED,
                bg=Theme.BG_SECONDARY,
                pady=30
            )
            no_profiles.pack()
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def _create_profile_item(self, parent, profile: ProfileInfo):
        """Create a single profile item in the list."""
        frame = tk.Frame(parent, bg=Theme.BG_SECONDARY, padx=15, pady=12)
        frame.pack(fill=tk.X)
        
        radio = tk.Radiobutton(
            frame,
            variable=self.selected_var,
            value=profile.name,
            bg=Theme.BG_SECONDARY,
            activebackground=Theme.BG_SECONDARY,
            selectcolor=Theme.ACCENT_PRIMARY
        )
        radio.pack(side=tk.LEFT)
        
        info_frame = tk.Frame(frame, bg=Theme.BG_SECONDARY)
        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        name_text = profile.name
        if profile.is_default:
            name_text += " ⭐"
        
        name_label = tk.Label(
            info_frame,
            text=name_text,
            font=('Segoe UI', 11, 'bold'),
            fg=Theme.TEXT_PRIMARY,
            bg=Theme.BG_SECONDARY,
            anchor='w'
        )
        name_label.pack(fill=tk.X)
        
        username_label = tk.Label(
            info_frame,
            text=f"Username: {profile.username}",
            font=('Segoe UI', 9),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_SECONDARY,
            anchor='w'
        )
        username_label.pack(fill=tk.X)
        
        if profile.last_used:
            last_used = tk.Label(
                info_frame,
                text=f"Last used: {profile.last_used[:16]}",
                font=('Segoe UI', 8),
                fg=Theme.TEXT_MUTED,
                bg=Theme.BG_SECONDARY,
                anchor='w'
            )
            last_used.pack(fill=tk.X)
        
        separator = tk.Frame(parent, bg=Theme.BORDER_NORMAL, height=1)
        separator.pack(fill=tk.X)
    
    def _create_action_buttons(self, parent):
        """Create profile management action buttons."""
        action_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        action_frame.pack(fill=tk.X, pady=(0, 15))
        
        actions = [
            ("➕ Add", "add"),
            ("✏️ Edit", "edit"),
            ("⭐ Set Default", "default"),
            ("🗑️ Delete", "delete")
        ]
        
        for text, action in actions:
            btn = tk.Button(
                action_frame,
                text=text,
                font=('Segoe UI', 9),
                bg=Theme.BG_TERTIARY,
                fg=Theme.TEXT_PRIMARY,
                activebackground=Theme.BORDER_NORMAL,
                relief=tk.FLAT,
                cursor='hand2',
                command=lambda a=action: self._on_action(a),
                padx=10
            )
            btn.pack(side=tk.LEFT, padx=(0, 8))
    
    def _create_main_buttons(self, parent):
        """Create main action buttons."""
        button_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        button_frame.pack(fill=tk.X)
        
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            font=('Segoe UI', 10),
            bg=Theme.BG_TERTIARY,
            fg=Theme.TEXT_PRIMARY,
            activebackground=Theme.BORDER_NORMAL,
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_cancel,
            width=12
        )
        cancel_btn.pack(side=tk.LEFT)
        
        select_btn = tk.Button(
            button_frame,
            text="Use Selected Profile",
            font=('Segoe UI', 10, 'bold'),
            bg=Theme.ACCENT_PRIMARY,
            fg=Theme.BG_PRIMARY,
            activebackground=Theme.ACCENT_SECONDARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_select,
            width=18
        )
        select_btn.pack(side=tk.RIGHT)
    
    def _on_action(self, action: str):
        """Handle action button clicks."""
        self.action = action
        self.selected_profile = self.selected_var.get() if self.selected_var.get() else None
        self.root.destroy()
    
    def _on_select(self):
        """Handle profile selection."""
        selected = self.selected_var.get()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a profile.")
            return
        
        self.action = "select"
        self.selected_profile = selected
        self.root.destroy()
    
    def _on_cancel(self):
        """Handle dialog cancellation."""
        self.cancelled = True
        self.root.destroy()
    
    def show(self) -> Optional[dict]:
        """
        Display the dialog and wait for user input.
        
        Returns:
            Dictionary with action and selected profile, or None if cancelled.
        """
        self.root.mainloop()
        
        if self.cancelled:
            return None
        
        return {
            'action': self.action,
            'profile': self.selected_profile
        }


# ============================================================================
# ADD/EDIT PROFILE DIALOG
# ============================================================================

class ProfileEditorDialog:
    """
    Dialog for adding or editing a credential profile.
    """
    
    def __init__(self, existing_profile: Optional[ProfileInfo] = None,
                 parent: Optional[tk.Tk] = None):
        """
        Initialize the profile editor dialog.
        
        Args:
            existing_profile: Profile to edit, or None for new profile
            parent: Optional parent window
        """
        self.existing = existing_profile
        self.result: Optional[dict] = None
        self.cancelled: bool = False
        
        if parent:
            self.root = tk.Toplevel(parent)
        else:
            self.root = tk.Tk()
        
        self._setup_window()
        self._create_widgets()
    
    def _setup_window(self):
        """Configure the dialog window."""
        title = "✏️ Edit Profile" if self.existing else "➕ Add Profile"
        self.root.title(title)
        self.root.resizable(True, True) 
        self.root.configure(bg=Theme.BG_PRIMARY)
        
        width, height = 420, 350
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_cancel)
    
    def _create_widgets(self):
        """Create all dialog widgets."""
        main_frame = tk.Frame(self.root, bg=Theme.BG_PRIMARY, padx=35, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        title_text = "✏️ Edit Profile" if self.existing else "➕ Add New Profile"
        title = tk.Label(
            main_frame,
            text=title_text,
            font=('Segoe UI', 16, 'bold'),
            fg=Theme.ACCENT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        title.pack(pady=(0, 20))
        
        self._create_field(main_frame, "Profile Name:", "name_entry")
        
        self._create_field(main_frame, "Username:", "username_entry")
        
        self._create_field(main_frame, "Password:", "password_entry", is_password=True)
        
        self.default_var = tk.BooleanVar(value=self.existing.is_default if self.existing else False)
        checkbox = tk.Checkbutton(
            main_frame,
            text="Set as default profile",
            variable=self.default_var,
            font=('Segoe UI', 10),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_PRIMARY,
            selectcolor=Theme.BG_TERTIARY,
            activebackground=Theme.BG_PRIMARY
        )
        checkbox.pack(anchor=tk.W, pady=(10, 20))
        
        if self.existing:
            self.name_entry.insert(0, self.existing.name)
            self.username_entry.insert(0, self.existing.username)
        
        self._create_buttons(main_frame)
        
        self.name_entry.focus_set()
        self.root.bind('<Return>', lambda e: self._on_submit())
    
    def _create_field(self, parent, label_text: str, attr_name: str, 
                     is_password: bool = False):
        """Create an input field."""
        frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        frame.pack(fill=tk.X, pady=(0, 12))
        
        label = tk.Label(
            frame,
            text=label_text,
            font=('Segoe UI', 10),
            fg=Theme.TEXT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        label.pack(anchor=tk.W)
        
        entry = tk.Entry(
            frame,
            font=('Segoe UI', 11),
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT_PRIMARY,
            insertbackground=Theme.ACCENT_PRIMARY,
            relief=tk.FLAT,
            highlightthickness=2,
            highlightbackground=Theme.BORDER_NORMAL,
            highlightcolor=Theme.BORDER_FOCUS,
            show='•' if is_password else ''
        )
        entry.pack(fill=tk.X, pady=(5, 0), ipady=8)
        setattr(self, attr_name, entry)
    
    def _create_buttons(self, parent):
        """Create action buttons."""
        button_frame = tk.Frame(parent, bg=Theme.BG_PRIMARY)
        button_frame.pack(fill=tk.X)
        
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            font=('Segoe UI', 10),
            bg=Theme.BG_TERTIARY,
            fg=Theme.TEXT_PRIMARY,
            activebackground=Theme.BORDER_NORMAL,
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_cancel,
            width=12
        )
        cancel_btn.pack(side=tk.LEFT)
        
        submit_text = "Save Changes" if self.existing else "Add Profile"
        submit_btn = tk.Button(
            button_frame,
            text=submit_text,
            font=('Segoe UI', 10, 'bold'),
            bg=Theme.ACCENT_PRIMARY,
            fg=Theme.BG_PRIMARY,
            activebackground=Theme.ACCENT_SECONDARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_submit,
            width=14
        )
        submit_btn.pack(side=tk.RIGHT)
    
    def _on_submit(self):
        """Handle form submission."""
        name = self.name_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not name:
            messagebox.showerror("Error", "Please enter a profile name.")
            return
        
        if not username:
            messagebox.showerror("Error", "Please enter a username.")
            return
        
        if not password and not self.existing:
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        self.result = {
            'name': name,
            'username': username,
            'password': password if password else None,
            'is_default': self.default_var.get(),
            'original_name': self.existing.name if self.existing else None
        }
        
        self.root.destroy()
    
    def _on_cancel(self):
        """Handle dialog cancellation."""
        self.cancelled = True
        self.root.destroy()
    
    def show(self) -> Optional[dict]:
        """
        Display the dialog and wait for user input.
        
        Returns:
            Dictionary with profile data, or None if cancelled.
        """
        self.root.mainloop()
        return self.result if not self.cancelled else None


# ============================================================================
# SECURITY INFO DIALOG
# ============================================================================

class SecurityInfoDialog:
    """
    Dialog displaying security information and settings.
    """
    
    def __init__(self, security_info: dict, parent: Optional[tk.Tk] = None):
        """
        Initialize the security info dialog.
        
        Args:
            security_info: Dictionary with security information
            parent: Optional parent window
        """
        self.info = security_info
        
        if parent:
            self.root = tk.Toplevel(parent)
        else:
            self.root = tk.Tk()
        
        self._setup_window()
        self._create_widgets()
    
    def _setup_window(self):
        """Configure the dialog window."""
        self.root.title("🔒 Security Information")
        self.root.resizable(True, True)  
        self.root.configure(bg=Theme.BG_PRIMARY)
        
        width, height = 500, 380
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def _create_widgets(self):
        """Create all dialog widgets."""
        main_frame = tk.Frame(self.root, bg=Theme.BG_PRIMARY, padx=30, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title = tk.Label(
            main_frame,
            text="🔒 Security Information",
            font=('Segoe UI', 18, 'bold'),
            fg=Theme.ACCENT_PRIMARY,
            bg=Theme.BG_PRIMARY
        )
        title.pack(pady=(0, 20))
        
        info_frame = tk.Frame(main_frame, bg=Theme.BG_SECONDARY, padx=20, pady=15)
        info_frame.pack(fill=tk.BOTH, expand=True)
        
        items = [
            ("📁 Storage Location", self.info.get('storage_path', 'Unknown')),
            ("🔐 Encryption Method", self.info.get('encryption_method', 'AES-256')),
            ("🔑 Master Password", "Set ✓" if self.info.get('master_password_set') else "Not Set"),
            ("👤 Stored Profiles", str(self.info.get('total_profiles', 0))),
            ("🖐️ Biometric Support", "Available ✓" if self.info.get('biometric_available') else "Not Available"),
            ("🖐️ Biometric Enabled", "Yes ✓" if self.info.get('biometric_enabled') else "No"),
        ]
        
        for label, value in items:
            self._create_info_row(info_frame, label, value)
        
        note_frame = tk.Frame(main_frame, bg=Theme.BG_TERTIARY, padx=15, pady=12)
        note_frame.pack(fill=tk.X, pady=(15, 0))
        
        note = tk.Label(
            note_frame,
            text="🛡️ Your credentials are protected with industry-standard encryption.\n"
                 "The master password is never stored - only a secure hash is kept for verification.",
            font=('Segoe UI', 9),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_TERTIARY,
            justify=tk.LEFT,
            wraplength=430
        )
        note.pack()
        
        close_btn = tk.Button(
            main_frame,
            text="Close",
            font=('Segoe UI', 10),
            bg=Theme.ACCENT_PRIMARY,
            fg=Theme.BG_PRIMARY,
            activebackground=Theme.ACCENT_SECONDARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self.root.destroy,
            width=12
        )
        close_btn.pack(pady=(15, 0))
    
    def _create_info_row(self, parent, label: str, value: str):
        """Create an info row."""
        row = tk.Frame(parent, bg=Theme.BG_SECONDARY)
        row.pack(fill=tk.X, pady=4)
        
        label_widget = tk.Label(
            row,
            text=label,
            font=('Segoe UI', 10),
            fg=Theme.TEXT_SECONDARY,
            bg=Theme.BG_SECONDARY,
            width=20,
            anchor='w'
        )
        label_widget.pack(side=tk.LEFT)
        
        value_widget = tk.Label(
            row,
            text=value,
            font=('Segoe UI', 10),
            fg=Theme.TEXT_PRIMARY,
            bg=Theme.BG_SECONDARY,
            anchor='w'
        )
        value_widget.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def show(self):
        """Display the dialog."""
        self.root.mainloop()


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("Testing Master Password Dialog (Setup Mode)...")
    dialog = MasterPasswordDialog(mode="setup")
    result = dialog.show()
    print(f"Result: {result}")
    
    print("\nTesting Profile Selection Dialog...")
    test_profiles = [
        ProfileInfo("Default", "user1", True, "2024-01-15T10:30:00"),
        ProfileInfo("Work", "work_user", False, "2024-01-14T08:00:00"),
        ProfileInfo("Test", "test_account", False),
    ]
    selection_dialog = ProfileSelectionDialog(test_profiles)
    result = selection_dialog.show()
    print(f"Result: {result}")
