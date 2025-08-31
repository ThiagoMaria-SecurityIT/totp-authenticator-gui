# TOTP Authenticator GUI

A desktop GUI application for generating Time-based One-Time Passwords (TOTP) for two-factor authentication. Built with Python and Tkinter, featuring a modern dark theme and enterprise-grade security.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)  

<img width="855" height="572" alt="image" src="https://github.com/user-attachments/assets/06a895f0-a236-40e8-aa7c-bca4046ae194" />  


> [!CAUTION]
> - **NEVER remove accounts from this authenticator without first disabling 2FA on the actual service (Google account, Amazon account, Github account, etc).**  
> - **Doing so will result in permanent lockout from your accounts.**
> - **You can use the example accounts [here](#for-testing-only) to test this tool**   

> [!WARNING]
> - The Restore feature erases all the current accounts  
> - Backup your current accounts before Restore or you will lost them forever  

## Features

### Core Functionality
- **Real-time TOTP Generation** - 6-digit codes refreshing every 30 seconds
- **Multi-Account Support** - Manage unlimited accounts in one secure location
- **Live Countdown Timer** - Visual progress bar and color-coded time remaining
- **Cross-Platform** - Works on Windows, macOS, and Linux

### Security Features
- **AES Encryption** - All secrets encrypted with PBKDF2 key derivation (100,000 iterations)
- **Master Password Protection** - Secure access to your authentication codes
- **Encrypted Backups** - Export accounts with separate password protection
- **Safety Warnings** - Built-in warnings prevent accidental account lockouts
- **Local Storage** - No cloud dependencies, all data stays on your device  
<img width="380" height="350" alt="image" src="https://github.com/user-attachments/assets/edd1a1d7-af4e-4419-b28b-9311b5b16d72" /> <img width="470" height="380" alt="image" src="https://github.com/user-attachments/assets/da8deaed-3073-4433-9663-b58126310d8b" />  

  

### User Interface
- **Modern Dark Theme** - Easy on the eyes with professional appearance
- **Intuitive Layout** - Clean, organized interface with clear visual hierarchy
- **Real-time Updates** - Live code generation with smooth countdown animations
- **Responsive Design** - Scales beautifully on different screen sizes

### Safety Features
- **Safety Check System** - Service-specific removal instructions with direct links
- **Enhanced Removal Warnings** - Multi-step confirmation prevents accidental deletions
- **Account Backup System** - Encrypted export functionality before making changes


## Requirements

- Python 3.7 or higher
- Tkinter (included with most Python installations)
- Required packages:
  ```
  pyotp>=2.6.0
  cryptography>=3.0.0
  ```

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ThiagoMaria-SecurityIT/totp-authenticator-gui.git
   cd totp-authenticator-gui
   ```

2. **Install dependencies:**
   ```bash
   pip install pyotp cryptography
   ```

3. **Run the application:**
   ```bash
   python authenticator_gui.py
   ```

> [!Tip]
> Yes, you have to run it with "python" and not "py"  

4. **If you prefer you can use the CLI version:***
   ```bash
   python authenticator.py
   ```
   
## Usage

>[!Tip]
>After click in the Backup button you have to write the password in the CLI too
>Confirm your Backup password in the CLI too  

### ⚠️ CRITICAL WARNING - 🔒 Account Lockout Prevention 🔒   

**Correct procedure:**
1. Go to the service's security settings, for example Google, Amazon, Github (use our Safety Check feature for links)
2. Disable 2FA or switch to a different authenticator method at Google, Github or Amazon security settings for MFA or 2FA (disable there first)  
3. Test that you can log in without this tool
4. Only then remove the account from this authenticator

> [!CAUTION]
> - NEVER remove accounts from this authenticator without first disabling 2FA on the actual service (Google, Github, Amazon, etc).  
> **If you remove an account from this tool first, you may lose access to your account forever.**  
> **Use example accounts below for demonstration purposes only, never for production**

### First Time Setup
1. Launch the application
2. Create a master password when prompted (first-time setup only)
3. Click **"➕ Add Account"** to add your first TOTP account

### Adding Accounts
1. Click "Add Account"
2. Enter a recognizable name (e.g., "Google", "GitHub")
3. Enter the secret key from your service's 2FA setup
4. Click "Add Account"

The secret key is the text string you get when setting up 2FA (usually shown alongside the QR code).

### **For Testing Only:🧪**   
Use these example accounts for demonstration purposes only, never for production:  
- **Google Test** with secret `JBSWY3DPEHPK3PXP`
- **GitHub Test** with secret `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`

### Managing Accounts
- **View Codes**: All active codes display automatically with countdown timers
- **Safety Check**: Click "Safety Check" for removal instructions and service links
- **Create Backup**: Click "Backup" to export encrypted account data
- **Remove Account**: Click "Remove" (use Safety Check first!)

### Security Best Practices
1. **Always use Safety Check** before removing any account
2. **Create regular backups** of your accounts
3. **Store backups securely** in a different location
4. **Use a strong master password** you won't forget

### How to Restore Your Accounts:  
>[!Warning]
> - The Restore feature erases all current accounts in this tool  
> - Before restore, **do a backup**  
> - Merge accounts is not implemented   

🖥️ GUI Method (Easy):
1. Click "📂 Restore" button in the GUI
2. Select your backup file (usually named like totp_backup_20241129_143052.enc)
3. Enter the backup password you used when creating the backup
4. Confirm the restore - it shows you which accounts will be restored
   
Done! Your accounts are back with all their secrets

## Interface Overview

### Main Window
- **Header**: Dark blue header with application title
- **Account List**: Real-time TOTP codes with account names
- **Timer Display**: Shows time remaining until next code generation
- **Progress Bar**: Visual countdown with color indicators
- **Control Buttons**: Add, Remove, Backup, Restore and Safety Check functions
- **Status Bar**: Current application status and account count

### Color Indicators
- **Green (20-30s)**: Plenty of time remaining
- **Orange (10-19s)**: Codes expiring soon
- **Red (0-9s)**: Codes about to expire

### Dialog Windows
- **Add Account**: Clean form with secret key visibility toggle
- **Remove Account**: Safety warnings with confirmation requirements
- **Safety Check**: Service-specific instructions with direct links
- **Backup Export**: Encrypted backup creation with password protection

## Supported Services

This authenticator works with any service supporting the TOTP standard (RFC 6238), including:

- **Google** (Gmail, Drive, etc.)
- **GitHub** 
- **Microsoft** (Office 365, Azure)
- **Discord**
- **Amazon Web Services**
- **Reddit**
- **Dropbox**
- **And thousands more...**

## File Structure

```
totp-authenticator-gui/
├── authenticator_gui.py      # Main GUI application
├── storage.py               # Encrypted storage module
├── authenticator.py         # CLI version (legacy)
└── README.md               # This file
```

## Data Storage

- **Configuration**: `~/.totp_authenticator/`
- **Encrypted Accounts**: `~/.totp_authenticator/accounts.json`
- **Encryption Salt**: `~/.totp_authenticator/salt.key`
- **Backups**: Current directory as `totp_backup_YYYYMMDD_HHMMSS.enc`

All files use restrictive permissions (600) for security.

## Important Security Notes

- **Never share your master password** - it protects all your accounts
- **Keep your secret keys private** - they provide access to your accounts
- **This tool generates valid codes** but doesn't connect to services directly
- **CRITICAL: Always disable 2FA on services first** before removing accounts from this tool
- **Account lockout risk**: Removing accounts from this tool before disabling 2FA on the service will cause permanent lockout
- **Store backups safely** - they contain all your authentication secrets
- **Example accounts only**: The test accounts provided in this documentation are for demonstration only

## Troubleshooting issues
- If you do not enter the correct password when (log in) opening this tool, it will open without any account
- You can find the folder .totp_authenticator searching %USERPROFILE% in your windows
- The folder .totp_authenticator has the session password, erasing the 2 files will not grant you access to the tool session without password
- Erase .totp_authenticator only if you backup your current session or you will lost all accounts
 - Backup is the key for any authenticator tool
- You can only restore the backup if you entered the correct password to log in
  - Deleting the .totp_authenticator folder will allow you to enter a new log in password and then restore the backups
    

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Python's Tkinter for cross-platform compatibility
- Uses PyOTP for RFC 6238 compliant TOTP generation
- Cryptography library for enterprise-grade encryption
- Inspired by popular authenticator apps but with enhanced security features

## Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Check existing documentation
- Review the Safety Check feature for service-specific guidance

---

**Quick Start**: `python authenticator_gui.py` → Create master password → Add test account → Start generating codes!
