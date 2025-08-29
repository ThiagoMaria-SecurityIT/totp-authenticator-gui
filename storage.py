"""
Secure storage module for TOTP secrets
Handles encryption and decryption of sensitive data
"""

import os
import json
import base64
import hashlib
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureStorage:
    def __init__(self):
        self.config_dir = Path.home() / '.totp_authenticator'
        self.config_file = self.config_dir / 'accounts.json'
        self.salt_file = self.config_dir / 'salt.key'
        self._ensure_config_dir()
        self._fernet = None
        self._master_password = None
    
    def _ensure_config_dir(self):
        """Create configuration directory if it doesn't exist"""
        self.config_dir.mkdir(mode=0o700, exist_ok=True)
    
    def _get_master_password(self):
        """Get or set master password for encryption"""
        if self._master_password is not None:
            return self._master_password
        
        # Check if this is first time setup
        if not self.config_file.exists():
            print("First time setup - Create a master password to secure your accounts")
            print("This password will encrypt your TOTP secrets")
            password = getpass.getpass("Create master password: ")
            confirm = getpass.getpass("Confirm master password: ")
            
            if password != confirm:
                raise ValueError("Passwords do not match")
            
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")
            
            self._master_password = password
        else:
            # Existing setup - ask for password
            self._master_password = getpass.getpass("Enter master password: ")
        
        return self._master_password
    
    def _get_salt(self):
        """Get or create encryption salt"""
        if self.salt_file.exists():
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            # Generate new salt
            salt = os.urandom(32)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            # Set restrictive permissions
            os.chmod(self.salt_file, 0o600)
            return salt
    
    def _get_fernet(self):
        """Get Fernet encryption instance"""
        if self._fernet is not None:
            return self._fernet
        
        try:
            password = self._get_master_password()
            salt = self._get_salt()
            
            # Derive encryption key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            self._fernet = Fernet(key)
            
            # Test decryption if file exists (validates password)
            if self.config_file.exists():
                self._load_accounts()  # This will raise exception if password is wrong
            
            return self._fernet
            
        except Exception as e:
            if "Invalid token" in str(e) or "decrypt" in str(e).lower():
                raise ValueError("Incorrect master password")
            raise
    
    def _load_accounts(self):
        """Load and decrypt accounts from storage"""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return {}
            
            fernet = self._get_fernet()
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
            
        except Exception as e:
            if "Invalid token" in str(e):
                raise ValueError("Cannot decrypt accounts - incorrect password or corrupted data")
            raise
    
    def _save_accounts(self, accounts):
        """Encrypt and save accounts to storage"""
        try:
            fernet = self._get_fernet()
            data = json.dumps(accounts, indent=2)
            encrypted_data = fernet.encrypt(data.encode())
            
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions
            os.chmod(self.config_file, 0o600)
            return True
            
        except Exception as e:
            print(f"Error saving accounts: {str(e)}")
            return False
    
    def add_account(self, name, secret):
        """Add a new account with encrypted secret"""
        try:
            accounts = self._load_accounts()
            
            # Store encrypted secret
            accounts[name] = {
                'secret': secret,
                'created': str(int(os.path.getmtime(self.config_file)) if self.config_file.exists() else 0)
            }
            
            return self._save_accounts(accounts)
            
        except Exception as e:
            print(f"Error adding account: {str(e)}")
            return False
    
    def remove_account(self, name):
        """Remove an account"""
        try:
            accounts = self._load_accounts()
            
            if name not in accounts:
                return False
            
            del accounts[name]
            return self._save_accounts(accounts)
            
        except Exception as e:
            print(f"Error removing account: {str(e)}")
            return False
    
    def get_secret(self, name):
        """Get decrypted secret for an account"""
        try:
            accounts = self._load_accounts()
            
            if name not in accounts:
                return None
            
            return accounts[name]['secret']
            
        except Exception as e:
            print(f"Error retrieving secret: {str(e)}")
            return None
    
    def list_accounts(self):
        """List all account names"""
        try:
            accounts = self._load_accounts()
            return list(accounts.keys())
            
        except Exception as e:
            print(f"Error listing accounts: {str(e)}")
            return []
    
    def account_exists(self, name):
        """Check if account exists"""
        try:
            accounts = self._load_accounts()
            return name in accounts
            
        except Exception as e:
            print(f"Error checking account: {str(e)}")
            return False
    
    def change_master_password(self):
        """Change the master password (re-encrypt all data)"""
        try:
            # Load accounts with current password
            accounts = self._load_accounts()
            
            print("Change master password")
            new_password = getpass.getpass("Enter new master password: ")
            confirm = getpass.getpass("Confirm new master password: ")
            
            if new_password != confirm:
                raise ValueError("Passwords do not match")
            
            if len(new_password) < 8:
                raise ValueError("Password must be at least 8 characters long")
            
            # Generate new salt
            new_salt = os.urandom(32)
            
            # Create new encryption instance
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=new_salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
            new_fernet = Fernet(key)
            
            # Save new salt
            with open(self.salt_file, 'wb') as f:
                f.write(new_salt)
            os.chmod(self.salt_file, 0o600)
            
            # Re-encrypt and save accounts
            data = json.dumps(accounts, indent=2)
            encrypted_data = new_fernet.encrypt(data.encode())
            
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            os.chmod(self.config_file, 0o600)
            
            # Update instance variables
            self._fernet = new_fernet
            self._master_password = new_password
            
            print("✓ Master password changed successfully")
            return True
            
        except Exception as e:
            print(f"Error changing master password: {str(e)}")
            return False
