#!/usr/bin/env python3
"""
TOTP Authenticator - Command-line two-factor authentication tool
Generates time-based one-time passwords for secure account access
"""

import argparse
import sys
import time
import os
import getpass
import re
import threading
import json
from datetime import datetime
import pyotp
from storage import SecureStorage


class TOTPAuthenticator:
    def __init__(self):
        self.storage = SecureStorage()
        self.running = False
        
    def add_account(self, name, secret=None):
        """Add a new TOTP account with secure secret input"""
        try:
            # Validate account name
            if not name or not name.strip():
                print("Error: Account name cannot be empty")
                return False
                
            name = name.strip()
            
            # Check if account already exists
            if self.storage.account_exists(name):
                print(f"Error: Account '{name}' already exists")
                return False
            
            # Get secret from user if not provided
            if not secret:
                print(f"Enter the secret key for '{name}':")
                print("(This will be hidden for security)")
                secret = getpass.getpass("Secret: ").strip()
            
            # Validate secret key format
            if not self._validate_secret(secret):
                print("Error: Invalid secret key format")
                print("Secret should be base32 encoded (A-Z, 2-7)")
                return False
            
            # Test TOTP generation to ensure secret is valid
            try:
                totp = pyotp.TOTP(secret)
                totp.now()  # Test generation
            except Exception as e:
                print(f"Error: Invalid secret key - {str(e)}")
                return False
            
            # Store the account
            if self.storage.add_account(name, secret):
                print(f"✓ Account '{name}' added successfully")
                return True
            else:
                print("Error: Failed to store account")
                return False
                
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return False
        except Exception as e:
            print(f"Error adding account: {str(e)}")
            return False
    
    def remove_account(self, name):
        """Remove a TOTP account with enhanced safety warnings"""
        try:
            if not self.storage.account_exists(name):
                print(f"Error: Account '{name}' not found")
                return False
            
            # Enhanced safety warnings
            print(f"⚠️  WARNING: Removing '{name}' from this authenticator tool")
            print("❗ CRITICAL: Have you ALREADY disabled 2FA on the actual service?")
            print("")
            print("🔒 REQUIRED STEPS BEFORE REMOVAL:")
            print(f"   1. Go to {name}'s security settings")
            print("   2. Either DISABLE 2FA completely OR switch to different authenticator")
            print("   3. Test that you can still log in without this tool")
            print("")
            print("💀 WARNING: If you skip these steps, you may be LOCKED OUT!")
            print("")
            
            # Strong confirmation required
            print("To proceed, type EXACTLY: 'I HAVE DISABLED 2FA'")
            confirm = input("Confirmation: ").strip()
            
            if confirm != "I HAVE DISABLED 2FA":
                print("❌ Removal cancelled for your safety")
                print("   Please disable 2FA on the service first, then try again")
                return False
            
            if self.storage.remove_account(name):
                print(f"✓ Account '{name}' removed successfully")
                return True
            else:
                print("Error: Failed to remove account")
                return False
                
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return False
        except Exception as e:
            print(f"Error removing account: {str(e)}")
            return False
    
    def list_accounts(self):
        """List all stored accounts"""
        try:
            accounts = self.storage.list_accounts()
            
            if not accounts:
                print("No accounts stored")
                return
            
            print(f"\nStored accounts ({len(accounts)}):")
            print("-" * 40)
            for i, account in enumerate(sorted(accounts), 1):
                print(f"{i:2d}. {account}")
            print()
            
        except Exception as e:
            print(f"Error listing accounts: {str(e)}")
    
    def safety_check(self):
        """Display safety information and removal instructions for all accounts"""
        try:
            accounts = self.storage.list_accounts()
            
            if not accounts:
                print("No accounts stored")
                return
            
            print("🔒 TOTP Authenticator Safety Check")
            print("=" * 50)
            print("📋 Your accounts and how to safely remove 2FA:")
            print()
            
            # Service-specific instructions
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
                # Try to match account to known service
                account_lower = account.lower()
                service_key = 'default'
                for key in service_info.keys():
                    if key in account_lower:
                        service_key = key
                        break
                
                info = service_info[service_key]
                
                print(f"{i}. 📱 {account}")
                print(f"   🌐 Settings URL: {info['url']}")
                print(f"   📝 Steps: {info['steps']}")
                print()
            
            print("⚠️  IMPORTANT SAFETY REMINDERS:")
            print("   • NEVER remove accounts from this tool without disabling 2FA first")
            print("   • Always test login after changing 2FA settings")
            print("   • Keep backup codes or alternative 2FA methods ready")
            print("   • Contact service support if you get locked out")
            print()
            print("🔧 To safely remove an account:")
            print("   1. Use the URLs above to disable 2FA on the service")
            print("   2. Test that you can log in without 2FA")
            print("   3. Then use: python authenticator.py --remove \"AccountName\"")
            
        except Exception as e:
            print(f"Error in safety check: {str(e)}")
    
    def backup_accounts(self, backup_file=None):
        """Export all account secrets to an encrypted backup file"""
        try:
            accounts = self.storage.list_accounts()
            
            if not accounts:
                print("No accounts to backup")
                return False
            
            # Generate backup filename if not provided
            if not backup_file:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_file = f"totp_backup_{timestamp}.enc"
            
            print(f"🔐 Creating encrypted backup of {len(accounts)} accounts...")
            print(f"📁 Backup file: {backup_file}")
            print()
            
            # Get all account data
            backup_data = {}
            for account in accounts:
                secret = self.storage.get_secret(account)
                if secret:
                    backup_data[account] = {
                        'secret': secret,
                        'exported': datetime.now().isoformat(),
                        'tool_version': '1.0.0'
                    }
            
            if not backup_data:
                print("Error: No valid account data to backup")
                return False
            
            # Create backup with password protection
            print("Enter a password to encrypt the backup file:")
            print("(This can be different from your master password)")
            backup_password = getpass.getpass("Backup password: ").strip()
            
            if len(backup_password) < 8:
                print("Error: Backup password must be at least 8 characters")
                return False
            
            # Encrypt backup data
            import base64
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.fernet import Fernet
            
            # Generate salt for backup encryption
            backup_salt = os.urandom(32)
            
            # Derive encryption key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=backup_salt,
                iterations=100000,
            )
            backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode()))
            backup_fernet = Fernet(backup_key)
            
            # Prepare data for encryption
            backup_json = json.dumps(backup_data, indent=2)
            encrypted_backup = backup_fernet.encrypt(backup_json.encode())
            
            # Create final backup file with salt + encrypted data
            final_backup = {
                'salt': base64.b64encode(backup_salt).decode(),
                'data': base64.b64encode(encrypted_backup).decode(),
                'version': '1.0.0',
                'created': datetime.now().isoformat(),
                'accounts': len(backup_data)
            }
            
            # Write backup file
            with open(backup_file, 'w') as f:
                json.dump(final_backup, f, indent=2)
            
            # Set restrictive permissions
            os.chmod(backup_file, 0o600)
            
            print(f"✓ Backup created successfully!")
            print(f"📊 Exported {len(backup_data)} accounts")
            print(f"🔒 File: {backup_file}")
            print()
            print("⚠️  IMPORTANT:")
            print("   • Store this backup file in a safe location")
            print("   • Remember the backup password - it's needed to restore")
            print("   • This file contains all your TOTP secrets!")
            
            return True
            
        except KeyboardInterrupt:
            print("\nBackup cancelled")
            return False
        except Exception as e:
            print(f"Error creating backup: {str(e)}")
            return False
    
    def generate_codes(self, account_name=None):
        """Generate and display TOTP codes with countdown"""
        try:
            accounts = self.storage.list_accounts()
            
            if not accounts:
                print("No accounts stored. Add an account first with: --add")
                return
            
            # Filter accounts if specific account requested
            if account_name:
                if account_name not in accounts:
                    print(f"Error: Account '{account_name}' not found")
                    return
                accounts = [account_name]
            
            self.running = True
            print("Press Ctrl+C to stop\n")
            
            try:
                while self.running:
                    self._display_codes(accounts)
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("\n\nStopped")
                
        except Exception as e:
            print(f"Error generating codes: {str(e)}")
        finally:
            self.running = False
    
    def _display_codes(self, accounts):
        """Display current TOTP codes with countdown timer"""
        # Clear screen (cross-platform)
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("TOTP Authenticator")
        print("=" * 50)
        print(f"Current time: {datetime.now().strftime('%H:%M:%S')}")
        print()
        
        # Calculate time remaining in current 30-second window
        current_time = int(time.time())
        time_remaining = 30 - (current_time % 30)
        
        # Progress bar for time remaining
        progress = "█" * (time_remaining // 2) + "░" * ((30 - time_remaining) // 2)
        print(f"Time remaining: {time_remaining:2d}s [{progress}]")
        print()
        
        # Display codes for each account
        for account in sorted(accounts):
            try:
                secret = self.storage.get_secret(account)
                if secret:
                    totp = pyotp.TOTP(secret)
                    code = totp.now()
                    
                    # Format code with spaces for readability
                    formatted_code = f"{code[:3]} {code[3:]}"
                    print(f"{account:20s} : {formatted_code}")
                else:
                    print(f"{account:20s} : ERROR - Cannot retrieve secret")
                    
            except Exception as e:
                print(f"{account:20s} : ERROR - {str(e)}")
        
        print()
        print("Press Ctrl+C to stop")
    
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


def main():
    """Main entry point with command-line argument parsing"""
    parser = argparse.ArgumentParser(
        description="TOTP Authenticator - Generate time-based two-factor authentication codes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --add "Google"           Add a new account
  %(prog)s --list                   List all accounts  
  %(prog)s --generate               Show codes for all accounts
  %(prog)s --generate "Google"      Show code for specific account
  %(prog)s --safety-check           Show safety info and removal instructions
  %(prog)s --backup                 Create encrypted backup of all accounts
  %(prog)s --remove "Google"        Remove an account (use safety-check first!)
        """
    )
    
    parser.add_argument(
        '--add', 
        metavar='ACCOUNT',
        help='Add a new TOTP account'
    )
    
    parser.add_argument(
        '--remove',
        metavar='ACCOUNT', 
        help='Remove a TOTP account'
    )
    
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all stored accounts'
    )
    
    parser.add_argument(
        '--generate',
        nargs='?',
        const='ALL',
        metavar='ACCOUNT',
        help='Generate TOTP codes (all accounts or specific account)'
    )
    
    parser.add_argument(
        '--safety-check',
        action='store_true',
        help='Show safety information and links for all accounts'
    )
    
    parser.add_argument(
        '--backup',
        nargs='?',
        const=None,
        metavar='FILENAME',
        help='Create encrypted backup of all accounts'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='TOTP Authenticator 1.0.0'
    )
    
    args = parser.parse_args()
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Initialize authenticator
    auth = TOTPAuthenticator()
    
    try:
        # Execute requested operation
        if args.add:
            auth.add_account(args.add)
            
        elif args.remove:
            auth.remove_account(args.remove)
            
        elif args.list:
            auth.list_accounts()
            
        elif args.safety_check:
            auth.safety_check()
            
        elif args.backup is not None:
            auth.backup_accounts(args.backup)
            
        elif args.generate is not None:
            if args.generate == 'ALL':
                auth.generate_codes()
            else:
                auth.generate_codes(args.generate)
                
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
