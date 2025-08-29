#!/usr/bin/env python3
"""
TOTP Authenticator GUI - Tkinter-based two-factor authentication tool
Generates time-based one-time passwords with a user-friendly interface
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time 
import re
from datetime import datetime
import pyotp
from storage import SecureStorage


class TOTPAuthenticatorGUI:
    def __init__(self):
        self.storage = SecureStorage()
        self.running = False
        self.master_password = None
        self.root = tk.Tk()
        
        # Get master password first
        if not self._get_master_password():
            self.root.destroy()
            return
            
        self.setup_gui()
        self.accounts_data = {}
        self.start_timer()
        
    def setup_gui(self):
        """Setup the main GUI window and components"""
        self.root.title("TOTP Authenticator")
        self.root.geometry("600x500")
        self.root.minsize(500, 400)
        self.root.configure(bg="#1a1a1a")  # Dark background
        
        # Configure grid weights for responsiveness
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        # Create header frame
        header_frame = tk.Frame(self.root, bg="#0d1117", height=60)
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_propagate(False)
        header_frame.grid_columnconfigure(0, weight=1)
        
        # Header title
        title_label = tk.Label(
            header_frame, 
            text="🔐 TOTP Authenticator", 
            font=("Arial", 16, "bold"),
            fg="#f0f6fc", 
            bg="#0d1117"
        )
        title_label.grid(row=0, column=0, pady=15)
        
        # Create main content frame
        main_frame = tk.Frame(self.root, bg="#1a1a1a")
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)
        
        # Create accounts listbox with scrollbar
        list_frame = tk.Frame(main_frame, bg="#1a1a1a")
        list_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)
        
        # Accounts listbox
        self.accounts_listbox = tk.Listbox(
            list_frame, 
            font=("Courier", 12),
            height=15,
            selectmode=tk.SINGLE,
            bg="#21262d",
            fg="#f0f6fc",
            selectbackground="#388bfd",
            selectforeground="white",
            borderwidth=0,
            highlightthickness=1,
            highlightcolor="#388bfd"
        )
        self.accounts_listbox.grid(row=0, column=0, sticky="nsew")
        
        # Scrollbar for listbox
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", bg="#30363d", troughcolor="#21262d")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Connect scrollbar to listbox
        self.accounts_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.accounts_listbox.yview)
        
        # Time remaining label
        self.time_label = tk.Label(
            main_frame, 
            text="Time remaining: 30s",
            font=("Arial", 12, "bold"),
            fg="#7dd3fc",
            bg="#1a1a1a"
        )
        self.time_label.grid(row=1, column=0, pady=(0, 10))
        
        # Progress bar for countdown
        self.progress = ttk.Progressbar(
            main_frame, 
            length=300, 
            mode='determinate',
            maximum=30
        )
        self.progress.grid(row=2, column=0, pady=(0, 15))
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg="#1a1a1a")
        buttons_frame.grid(row=3, column=0, pady=10)
        
        # Create buttons with dark theme
        self.add_btn = tk.Button(
            buttons_frame, 
            text="➕ Add Account", 
            command=self.add_account_dialog,
            bg="#238636", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20, 
            pady=8,
            borderwidth=0,
            activebackground="#2ea043"
        )
        self.add_btn.grid(row=0, column=0, padx=5)
        
        self.remove_btn = tk.Button(
            buttons_frame, 
            text="🗑️ Remove", 
            command=self.remove_account_dialog,
            bg="#da3633", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20, 
            pady=8,
            borderwidth=0,
            activebackground="#f85149"
        )
        self.remove_btn.grid(row=0, column=1, padx=5)
        
        self.backup_btn = tk.Button(
            buttons_frame, 
            text="💾 Backup", 
            command=self.backup_dialog,
            bg="#0969da", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20, 
            pady=8,
            borderwidth=0,
            activebackground="#1f6feb"
        )
        self.backup_btn.grid(row=0, column=2, padx=5)
        
        self.safety_btn = tk.Button(
            buttons_frame, 
            text="🔒 Safety Check", 
            command=self.safety_check_dialog,
            bg="#fb8500", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20, 
            pady=8,
            borderwidth=0,
            activebackground="#fd7e14"
        )
        self.safety_btn.grid(row=0, column=3, padx=5)
        
        # Status bar
        self.status_label = tk.Label(
            self.root, 
            text="Ready - Add an account to get started",
            relief=tk.SUNKEN, 
            anchor=tk.W,
            bg="#21262d",
            fg="#7d8590",
            font=("Arial", 9)
        )
        self.status_label.grid(row=2, column=0, sticky="ew")
        
    def start_timer(self):
        """Start the real-time update timer"""
        self.running = True
        self.update_codes()
        
    def update_codes(self):
        """Update TOTP codes and countdown timer"""
        if not self.running:
            return
            
        try:
            # Get current accounts
            accounts = self.storage.list_accounts(self.master_password)
            
            # Calculate time remaining in current 30-second window
            current_time = int(time.time())
            time_remaining = 30 - (current_time % 30)
            
            # Update progress bar and time label
            self.progress['value'] = time_remaining
            self.time_label.config(text=f"Time remaining: {time_remaining}s")
            
            # Update progress bar color based on time remaining
            if time_remaining <= 5:
                self.time_label.config(fg="#f85149")  # Red
            elif time_remaining <= 10:
                self.time_label.config(fg="#fb8500")  # Orange
            else:
                self.time_label.config(fg="#7dd3fc")  # Light blue
            
            # Clear and update accounts list
            self.accounts_listbox.delete(0, tk.END)
            
            if not accounts:
                self.accounts_listbox.insert(0, "No accounts added yet")
                self.accounts_listbox.insert(1, "Click 'Add Account' to get started")
                self.status_label.config(text="No accounts stored")
            else:
                for account in sorted(accounts):
                    try:
                        secret = self.storage.get_secret(account, self.master_password)
                        if secret:
                            totp = pyotp.TOTP(secret)
                            code = totp.now()
                            
                            # Format: "Account Name    123 456"
                            formatted_line = f"{account:<20} : {code[:3]} {code[3:]}"
                            self.accounts_listbox.insert(tk.END, formatted_line)
                        else:
                            self.accounts_listbox.insert(tk.END, f"{account:<20} : ERROR")
                    except Exception as e:
                        self.accounts_listbox.insert(tk.END, f"{account:<20} : ERROR")
                
                self.status_label.config(text=f"{len(accounts)} accounts loaded")
                        
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
        
        # Schedule next update
        if self.running:
            self.root.after(1000, self.update_codes)
    
    def add_account_dialog(self):
        """Show dialog to add a new account"""
        # Create dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title("Add TOTP Account")
        dialog.geometry("400x300")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 100,
            self.root.winfo_rooty() + 100
        ))
        
        # Account name entry
        tk.Label(dialog, text="Account Name:", font=("Arial", 12, "bold"), bg="#1a1a1a", fg="#f0f6fc").pack(pady=10)
        name_entry = tk.Entry(dialog, font=("Arial", 12), width=30, bg="#21262d", fg="#f0f6fc", insertbackground="white")
        name_entry.pack(pady=5)
        name_entry.focus()
        
        # Secret key entry
        tk.Label(dialog, text="Secret Key:", font=("Arial", 12, "bold"), bg="#1a1a1a", fg="#f0f6fc").pack(pady=(15, 5))
        tk.Label(dialog, text="(Base32 format: A-Z, 2-7)", font=("Arial", 9), fg="#7d8590", bg="#1a1a1a").pack()
        secret_entry = tk.Entry(dialog, font=("Arial", 12), width=40, show="*", bg="#21262d", fg="#f0f6fc", insertbackground="white")
        secret_entry.pack(pady=5)
        
        # Show/Hide secret button
        show_secret = tk.BooleanVar()
        def toggle_secret():
            if show_secret.get():
                secret_entry.config(show="")
            else:
                secret_entry.config(show="*")
        
        show_check = tk.Checkbutton(
            dialog, 
            text="Show secret", 
            variable=show_secret, 
            command=toggle_secret,
            bg="#1a1a1a",
            fg="#f0f6fc",
            selectcolor="#21262d",
            activebackground="#1a1a1a"
        )
        show_check.pack(pady=5)
        
        # Result label
        result_label = tk.Label(dialog, text="", fg="#f85149", bg="#1a1a1a")
        result_label.pack(pady=10)
        
        # Buttons
        button_frame = tk.Frame(dialog, bg="#1a1a1a")
        button_frame.pack(pady=20)
        
        def add_account():
            name = name_entry.get().strip()
            secret = secret_entry.get().strip()
            
            if not name:
                result_label.config(text="Account name cannot be empty", fg="red")
                return
            
            if not secret:
                result_label.config(text="Secret key cannot be empty", fg="red")
                return
            
            if self.storage.account_exists(name, self.master_password):
                result_label.config(text=f"Account '{name}' already exists", fg="red")
                return
            
            validation_result = self._validate_secret_detailed(secret)
            if validation_result != "valid":
                result_label.config(text=validation_result, fg="#f85149")
                return
            
            # Test TOTP generation
            try:
                totp = pyotp.TOTP(secret)
                totp.now()
            except Exception as e:
                result_label.config(text=f"Invalid secret: {str(e)}", fg="red")
                return
            
            # Add account
            try:
                if self.storage.add_account(name, secret, self.master_password):
                    result_label.config(text=f"✓ Account '{name}' added successfully!", fg="#7dd3fc")
                    self.root.after(1500, dialog.destroy)
                else:
                    result_label.config(text="Failed to store account - storage error", fg="#f85149")
            except Exception as e:
                result_label.config(text=f"Storage error: {str(e)}", fg="#f85149")
        
        tk.Button(
            button_frame, 
            text="Add Account", 
            command=add_account,
            bg="#238636", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20,
            borderwidth=0,
            activebackground="#2ea043"
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            button_frame, 
            text="Cancel", 
            command=dialog.destroy,
            bg="#6e7681", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20,
            borderwidth=0,
            activebackground="#8b949e"
        ).pack(side=tk.LEFT)
        
        # Bind Enter key to add account
        dialog.bind('<Return>', lambda e: add_account())
    
    def remove_account_dialog(self):
        """Show dialog to remove an account with safety warnings"""
        accounts = self.storage.list_accounts(self.master_password)
        
        if not accounts:
            messagebox.showinfo("No Accounts", "No accounts to remove")
            return
        
        # Create selection dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Remove Account - SAFETY WARNING")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        
        # Warning header
        warning_frame = tk.Frame(dialog, bg="#e74c3c")
        warning_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            warning_frame, 
            text="⚠️ SAFETY WARNING", 
            font=("Arial", 14, "bold"),
            bg="#e74c3c", 
            fg="white"
        ).pack(pady=10)
        
        # Warning text
        warning_text = tk.Text(dialog, height=8, wrap=tk.WORD, font=("Arial", 10))
        warning_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        warning_content = """⚠️  CRITICAL: Have you ALREADY disabled 2FA on the actual service?

🔒 REQUIRED STEPS BEFORE REMOVAL:
   1. Go to the service's security settings
   2. Either DISABLE 2FA completely OR switch to different authenticator
   3. Test that you can still log in without this tool

💀 WARNING: If you skip these steps, you may be LOCKED OUT!

Use 'Safety Check' button for service-specific instructions.
"""
        warning_text.insert(tk.END, warning_content)
        warning_text.config(state=tk.DISABLED)
        
        # Account selection
        tk.Label(dialog, text="Select account to remove:", font=("Arial", 11, "bold")).pack(pady=(10, 5))
        
        account_var = tk.StringVar()
        account_combo = ttk.Combobox(
            dialog, 
            textvariable=account_var, 
            values=sorted(accounts),
            state="readonly",
            font=("Arial", 11)
        )
        account_combo.pack(pady=5)
        
        # Confirmation entry
        tk.Label(
            dialog, 
            text="Type 'I HAVE DISABLED 2FA' to confirm:", 
            font=("Arial", 11, "bold"),
            fg="#e74c3c"
        ).pack(pady=(15, 5))
        
        confirm_entry = tk.Entry(dialog, font=("Arial", 11), width=30)
        confirm_entry.pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=20)
        
        def remove_account():
            account = account_var.get()
            confirmation = confirm_entry.get().strip()
            
            if not account:
                messagebox.showerror("Error", "Please select an account")
                return
            
            if confirmation != "I HAVE DISABLED 2FA":
                messagebox.showerror(
                    "Safety Check Failed", 
                    "You must type 'I HAVE DISABLED 2FA' exactly to proceed"
                )
                return
            
            if self.storage.remove_account(account, self.master_password):
                messagebox.showinfo("Success", f"Account '{account}' removed successfully")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to remove account")
        
        tk.Button(
            button_frame, 
            text="Remove Account", 
            command=remove_account,
            bg="#e74c3c", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            button_frame, 
            text="Cancel", 
            command=dialog.destroy,
            bg="#95a5a6", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20
        ).pack(side=tk.LEFT)
    
    def backup_dialog(self):
        """Show backup creation dialog"""
        accounts = self.storage.list_accounts(self.master_password)
        
        if not accounts:
            messagebox.showinfo("No Accounts", "No accounts to backup")
            return
        
        backup_password = simpledialog.askstring(
            "Backup Password",
            "Enter password to encrypt backup file:\n(This can be different from master password)",
            show='*'
        )
        
        if not backup_password:
            return
        
        if len(backup_password) < 8:
            messagebox.showerror("Error", "Backup password must be at least 8 characters")
            return
        
        try:
            # Import backup functionality from CLI version
            from authenticator import TOTPAuthenticator
            cli_auth = TOTPAuthenticator()
            
            # Use CLI backup method with our storage
            cli_auth.storage = self.storage
            
            # Generate timestamp filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f"totp_backup_{timestamp}.enc"
            
            if cli_auth.backup_accounts(backup_file):
                messagebox.showinfo(
                    "Backup Success", 
                    f"Backup created successfully!\n\nFile: {backup_file}\nAccounts: {len(accounts)}\n\nStore this file safely!"
                )
            else:
                messagebox.showerror("Backup Failed", "Failed to create backup")
                
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {str(e)}")
    
    def safety_check_dialog(self):
        """Show safety check information"""
        accounts = self.storage.list_accounts(self.master_password)
        
        if not accounts:
            messagebox.showinfo("No Accounts", "No accounts stored")
            return
        
        # Create safety check window
        dialog = tk.Toplevel(self.root)
        dialog.title("Safety Check - Account Removal Instructions")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        
        # Header
        header_frame = tk.Frame(dialog, bg="#f39c12")
        header_frame.pack(fill=tk.X)
        
        tk.Label(
            header_frame, 
            text="🔒 TOTP Authenticator Safety Check", 
            font=("Arial", 14, "bold"),
            bg="#f39c12", 
            fg="white"
        ).pack(pady=10)
        
        # Create text widget with scrollbar
        text_frame = tk.Frame(dialog)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("Arial", 10))
        scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Generate safety information (reuse from CLI version)
        safety_content = self._generate_safety_content(accounts)
        text_widget.insert(tk.END, safety_content)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        tk.Button(
            dialog, 
            text="Close", 
            command=dialog.destroy,
            bg="#95a5a6", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=30,
            pady=5
        ).pack(pady=10)
    
    def _generate_safety_content(self, accounts):
        """Generate safety check content"""
        content = "📋 Your accounts and how to safely remove 2FA:\n\n"
        
        service_info = {
            'google': {
                'url': 'https://myaccount.google.com/security',
                'steps': 'Go to Security → 2-Step Verification → Turn off or change method'
            },
            'github': {
                'url': 'https://github.com/settings/security',
                'steps': 'Go to Account security → Two-factor authentication → Disable or reconfigure'
            },
            'microsoft': {
                'url': 'https://mysignins.microsoft.com/security-info',
                'steps': 'Go to Security info → Authentication methods → Remove authenticator app'
            },
            'discord': {
                'url': 'https://discord.com/channels/@me (User Settings → My Account)',
                'steps': 'Go to My Account → Two-Factor Authentication → Remove 2FA or change method'
            },
            'amazon': {
                'url': 'https://www.amazon.com/gp/css/account/info/view.html',
                'steps': 'Go to Login & security → Two-Step Verification → Manage → Turn off or edit'
            },
            'default': {
                'url': 'Check the service\'s security/account settings',
                'steps': 'Look for "Security", "Two-Factor", or "2FA" settings'
            }
        }
        
        for i, account in enumerate(sorted(accounts), 1):
            account_lower = account.lower()
            service_key = 'default'
            for key in service_info.keys():
                if key in account_lower:
                    service_key = key
                    break
            
            info = service_info[service_key]
            
            content += f"{i}. 📱 {account}\n"
            content += f"   🌐 Settings URL: {info['url']}\n"
            content += f"   📝 Steps: {info['steps']}\n\n"
        
        content += """⚠️  IMPORTANT SAFETY REMINDERS:
   • NEVER remove accounts from this tool without disabling 2FA first
   • Always test login after changing 2FA settings
   • Keep backup codes or alternative 2FA methods ready
   • Contact service support if you get locked out

🔧 To safely remove an account:
   1. Use the URLs above to disable 2FA on the service
   2. Test that you can log in without 2FA
   3. Then use the 'Remove' button in this tool"""
        
        return content
    
    def _validate_secret(self, secret):
        """Validate secret key format (base32)"""
        if not secret:
            return False
        
        # Remove spaces and convert to uppercase
        secret = secret.replace(" ", "").upper()
        
        # Check if it's valid base32 (A-Z, 2-7, padding with =)
        base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
        
        # Must be at least 16 characters (128 bits recommended)
        if len(secret) < 16:
            return False
        
        return bool(base32_pattern.match(secret))
    
    def _validate_secret_detailed(self, secret):
        """Validate secret key and return detailed error message"""
        if not secret:
            return "Secret key cannot be empty"
        
        # Remove spaces and convert to uppercase
        secret_clean = secret.replace(" ", "").upper()
        
        # Check minimum length
        if len(secret_clean) < 16:
            return f"Secret too short: {len(secret_clean)} chars (minimum 16 required)"
        
        # Check for invalid characters
        import string
        valid_chars = set(string.ascii_uppercase[:26] + "234567=")
        invalid_chars = set(secret_clean) - valid_chars
        if invalid_chars:
            return f"Invalid characters: {', '.join(sorted(invalid_chars))} (use A-Z, 2-7 only)"
        
        # Check base32 pattern
        base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
        if not base32_pattern.match(secret_clean):
            return "Invalid Base32 format (use A-Z, 2-7, with optional = padding)"
        
        return "valid"
    
    def _get_master_password(self):
        """Get master password from user via GUI dialog"""
        import os
        config_file = os.path.expanduser('~/.totp_authenticator/accounts.json')
        is_first_time = not os.path.exists(config_file)
        
        if is_first_time:
            return self._password_setup_dialog()
        else:
            return self._password_login_dialog()
    
    def _password_setup_dialog(self):
        """First time setup - create master password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("First Time Setup")
        dialog.geometry("400x300")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 100,
            self.root.winfo_rooty() + 100
        ))
        
        # Header
        tk.Label(
            dialog, 
            text="First Time Setup", 
            font=("Arial", 16, "bold"),
            fg="#f0f6fc", 
            bg="#1a1a1a"
        ).pack(pady=20)
        
        tk.Label(
            dialog, 
            text="Create a master password to secure your TOTP accounts.",
            font=("Arial", 10),
            fg="#7d8590", 
            bg="#1a1a1a"
        ).pack(pady=5)
        
        # Password entry
        tk.Label(dialog, text="Master Password:", font=("Arial", 12, "bold"), bg="#1a1a1a", fg="#f0f6fc").pack(pady=(20, 5))
        password_entry = tk.Entry(dialog, show="*", font=("Arial", 12), width=25, bg="#21262d", fg="#f0f6fc", insertbackground="white")
        password_entry.pack(pady=5)
        password_entry.focus()
        
        # Confirm password entry
        tk.Label(dialog, text="Confirm Password:", font=("Arial", 12, "bold"), bg="#1a1a1a", fg="#f0f6fc").pack(pady=(15, 5))
        confirm_entry = tk.Entry(dialog, show="*", font=("Arial", 12), width=25, bg="#21262d", fg="#f0f6fc", insertbackground="white")
        confirm_entry.pack(pady=5)
        
        # Result label
        result_label = tk.Label(dialog, text="", fg="#f85149", bg="#1a1a1a")
        result_label.pack(pady=10)
        
        password_result = [None]
        
        def create_password():
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not password:
                result_label.config(text="Password cannot be empty")
                return
            
            if len(password) < 8:
                result_label.config(text="Password must be at least 8 characters")
                return
            
            if password != confirm:
                result_label.config(text="Passwords do not match")
                return
            
            password_result[0] = password
            dialog.destroy()
        
        # Buttons
        button_frame = tk.Frame(dialog, bg="#1a1a1a")
        button_frame.pack(pady=20)
        
        tk.Button(
            button_frame, 
            text="Create Password", 
            command=create_password,
            bg="#238636", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20,
            borderwidth=0
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            button_frame, 
            text="Exit", 
            command=lambda: dialog.destroy(),
            bg="#6e7681", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20,
            borderwidth=0
        ).pack(side=tk.LEFT)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: create_password())
        
        # Wait for dialog to close
        dialog.wait_window()
        
        if password_result[0]:
            self.master_password = password_result[0]
            return True
        return False
    
    def _password_login_dialog(self):
        """Login with existing master password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Master Password")
        dialog.geometry("350x200")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 125,
            self.root.winfo_rooty() + 150
        ))
        
        # Header
        tk.Label(
            dialog, 
            text="Enter Master Password", 
            font=("Arial", 14, "bold"),
            fg="#f0f6fc", 
            bg="#1a1a1a"
        ).pack(pady=20)
        
        # Password entry
        tk.Label(dialog, text="Master Password:", font=("Arial", 11), bg="#1a1a1a", fg="#f0f6fc").pack(pady=(10, 5))
        password_entry = tk.Entry(dialog, show="*", font=("Arial", 12), width=25, bg="#21262d", fg="#f0f6fc", insertbackground="white")
        password_entry.pack(pady=5)
        password_entry.focus()
        
        # Result label
        result_label = tk.Label(dialog, text="", fg="#f85149", bg="#1a1a1a")
        result_label.pack(pady=10)
        
        password_result = [None]
        
        def verify_password():
            password = password_entry.get()
            
            if not password:
                result_label.config(text="Password cannot be empty")
                return
            
            # Test password by trying to load accounts
            try:
                test_accounts = self.storage.list_accounts(password)
                password_result[0] = password
                dialog.destroy()
            except Exception as e:
                if "password" in str(e).lower() or "decrypt" in str(e).lower():
                    result_label.config(text="Incorrect password")
                else:
                    result_label.config(text=f"Error: {str(e)}")
                password_entry.delete(0, tk.END)
        
        # Buttons
        button_frame = tk.Frame(dialog, bg="#1a1a1a")
        button_frame.pack(pady=20)
        
        tk.Button(
            button_frame, 
            text="Login", 
            command=verify_password,
            bg="#238636", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20,
            borderwidth=0
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            button_frame, 
            text="Exit", 
            command=lambda: dialog.destroy(),
            bg="#6e7681", 
            fg="white", 
            font=("Arial", 10, "bold"),
            padx=20,
            borderwidth=0
        ).pack(side=tk.LEFT)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: verify_password())
        
        # Wait for dialog to close
        dialog.wait_window()
        
        if password_result[0]:
            self.master_password = password_result[0]
            return True
        return False
    
    def run(self):
        """Start the GUI application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle application closing"""
        self.running = False
        self.root.destroy()


def main():
    """Main entry point for GUI application"""
    try:
        app = TOTPAuthenticatorGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application failed to start: {str(e)}")


if __name__ == "__main__":
    main()