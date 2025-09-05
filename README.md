# 🔐 TOTP Authenticator GUI

A secure, standalone desktop application for managing Time-based One-Time Passwords (TOTP), built with Python and Tkinter. It features a modern dark theme and prioritizes enterprise-grade, local-first security.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)  

<p align="center">
  <img width="855" alt="TOTP Authenticator GUI" src="https://github.com/user-attachments/assets/06a895f0-a236-40e8-aa7c-bca4046ae194">
</p>   

1. Image of the Authenticator with two random example accounts (not real accounts) after logging in with password.  


> [!CAUTION]
> **CRITICAL SAFETY WARNING**  
> - **NEVER** remove an account from this application without **FIRST** disabling 2FA on the service's website (e.g., Google, GitHub).  
> - Doing so will likely result in **permanent account lockout**.  

## Table of Contents

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Installation & Setup](#-installation--setup)
- [Usage Guide](#-usage-guide)
  - [First-Time Setup](#first-time-setup)
  - [Adding & Managing Accounts](#adding--managing-accounts)
  - [Backup & Restore](#backup--restore)
- [Critical Security Information](#-critical-security-information)
  - [The Two-Password System](#the-two-password-system)
  - [Resetting the Application](#resetting-the-application)
- [For Testing Only](#-for-testing-only)
- [Supported Services](#-supported-services)
- [AI Transparency](#-ai-transparency)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

1.  **Clone & Install:**
    ```bash
    git clone https://github.com/ThiagoMaria-SecurityIT/totp-authenticator-gui.git
    cd totp-authenticator-gui
    pip install pyotp cryptography
    ```
2.  **Run the App:**
    ```bash
    python authenticator_gui.py
    ```
3.  **First Use:**
    *   Create a strong Master Password when prompted **(Don't forget it, or you will lose all accounts)**.
    *   Click **"➕ Add Account"** and use a test account secret to see it work.

## ✨ Features

*   **Secure Local Storage:** All secrets are encrypted on your local disk using AES-256-GCM and PBKDF2. Nothing is stored in the cloud.
*   **Master Password Protection:** The application and all live secrets are protected by a single, strong master password.
*   **Encrypted, Portable Backups:** Export your accounts into a portable, password-protected file that you can store securely anywhere.
*   **Real-time TOTP Generation:** View multiple 6-digit codes that refresh every 30 seconds, complete with a visual countdown timer.
*   **Built-in Safety Mechanisms:** The UI includes explicit warnings and multi-step confirmations to prevent accidental account lockouts.
*   **Modern UI:** A clean, responsive, dark-themed interface that is easy to navigate.

<p align="center">
  <img width="380" height="350" alt="Add Account Dialog" src="https://github.com/user-attachments/assets/edd1a1d7-af4e-4419-b28b-9311b5b16d72">
  <img width="470" height="380" alt="Safety Check Dialog" src="https://github.com/user-attachments/assets/da8deaed-3073-4433-9663-b58126310d8b">
</p>

---

## 🛠️ Installation & Setup

- Follow these steps to set up the project and its dependencies in an isolated environment.   
- Virtual Environment (venv) is a best practice that prevents conflicts with your system's main Python packages, but it's important to note that this is **not** a security container like Docker.

1.  **Requirements:**
    *   Python 3.7+
    *   The `pyotp` and `cryptography` libraries.

2.  **Clone the repository:**
    ```bash
    git clone https://github.com/ThiagoMaria-SecurityIT/totp-authenticator-gui.git
    cd totp-authenticator-gui
    ```

3.  **Create and Activate a Virtual Environment (Recommended):**
    This isolates the project's dependencies from your system's global Python installation.

    *   **On Windows:**
        ```bash
        # Create the environment
        python -m venv venv
        # Activate the environment
        .\venv\Scripts\activate
        ```

    *   **On macOS & Linux:**
        ```bash
        # Create the environment
        python3 -m venv venv
        # Activate the environment
        source venv/bin/activate
        ```
    > Your terminal prompt should now be prefixed with `(venv)`, indicating the environment is active.

4.  **Install Dependencies:**
    With the virtual environment active, install the required packages.
    ```bash
    pip install pyotp cryptography
    ```

5.  **Run the Application:**
    ```bash
    # For the GUI version
    python authenticator_gui.py

    # For the command-line version
    python authenticator.py
    ```  

> [!TIP]  
> - On some systems, you may need to use `python3` instead of `python`.  
> - The `py` command is specific to Windows and may not work, use `python authenticator.py`.      

    
## 📖 Usage Guide

### First-Time Setup
The first time you launch the application, you will be prompted to create a **Master Password**. This password encrypts your local vault and is required every time you open the app.

### Adding & Managing Accounts
*   **Add Account:** Click **"➕ Add Account"**, provide a name, and paste the Base32 secret key from your service provider.
*   **Safety Check:** Before removing an account, click **"🔒 Safety Check"** for service-specific instructions and direct links to disable 2FA on their website.
*   **Remove Account:** After disabling 2FA on the service's website, use the **"🗑️ Remove"** button to safely delete the entry from this tool.

### Backup & Restore
> [!WARNING]
> The **Restore** feature completely overwrites all accounts currently in the application. **Always create a fresh backup before restoring** if you have live data you don't want to lose.

*   **Create Backup:** Click **"💾 Backup"**. You will be prompted (in the command line) to create a **Backup Password**. This encrypts your accounts into a `.enc` file you can save anywhere.
*   **Restore from Backup:** Click **"📂 Restore"**, select your `.enc` backup file, and enter the specific **Backup Password** you used to create it.

## ‼️ Critical Security Information

### The Two-Password System
This application uses two distinct types of passwords. Understanding the difference is essential.

1.  **Master Password:**
    *   **Purpose:** Unlocks the application for daily use.
    *   **Protects:** The live `accounts.json` file stored on your computer.
    *   **If Lost:** You are locked out of the live app. You must reset the application to regain access.

2.  **Backup Password:**
    *   **Purpose:** Encrypts and decrypts a specific backup file (`.enc`).
    *   **Protects:** Your portable backup files. You can have different passwords for different backups.
    *   **If Lost:** That specific backup file is permanently unusable.

### Resetting the Application
If you forget your **Master Password**, you can reset the application.

1.  **Locate the configuration folder:** `~/.totp_authenticator/` (On Windows, search for `%USERPROFILE%\.totp_authenticator`).
2.  **IMPORTANT:** Check this folder for any backup files you may have accidentally saved there. Move them to a safe location.
3.  **Delete the contents** of the `.totp_authenticator` folder (specifically `accounts.json` and `salt.key`).
4.  Relaunch the application. You will be prompted to create a new Master Password.
5.  You can now restore your accounts from a backup file using its **Backup Password**.

## 🧪 For Testing Only
To safely test the application's features, use these non-production secrets:
*   **Google Test:** `JBSWY3DPEHPK3PXP`
*   **GitHub Test:** `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`

## 🌐 Supported Services
This tool works with any service that supports the TOTP standard (RFC 6238), including Google, GitHub, Microsoft, Discord, AWS, and thousands more.

## 🤖 AI Transparency
This tool was developed with the assistance of an AI, which helped generate boilerplate code and refine logic. All code was reviewed, validated, and structured by a human developer to meet security and functionality standards. If using this in a corporate environment, please adhere to your company's policies regarding AI-assisted tools.

## 🔧 Troubleshooting
*   **Incorrect Master Password:** If you enter the wrong password, the app will open but will appear empty. Close and try again.
*   **Cannot Restore Backup:** Ensure you are using the correct **Backup Password**, not the Master Password.
*   **Forgetting Master Password:** Follow the reset procedure outlined in the [Critical Security Information](#-critical-security-information) section.

## 🤝 Contributing
Contributions are welcome! Please fork the repository, create a feature branch, and open a pull request.

## 📜 License
This project is licensed under the MIT License.  

## About Me & Contact

**Thiago Maria - From Brazil to the World 🌎**  
*Senior Security Information Professional | Passionate Programmer | AI Developer*

With a professional background in security analysis and a deep passion for programming, I created this Github acc to share some knowledge about security information, cybersecurity, Python and AI development practices. Most of my work here focuses on implementing security-first at companies while maintaining usability and productivity.

Let's Connect:  

👇🏽 Click on the badges below and msg me if you want to know how AI found "example accounts" for this project:   

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://www.linkedin.com/in/thiago-cequeira-99202239/)  
[![Hugging Face](https://img.shields.io/badge/🤗Hugging_Face-AI_projects-yellow)](https://huggingface.co/ThiSecur)  
 
## Ways to Contribute:   
 Want to see more upgrades? Help me keep it updated!    
 [![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-red)](https://github.com/sponsors/ThiagoMaria-SecurityIT) 
