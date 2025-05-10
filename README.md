# Trustedinstaller

`permissions_manager.sh` is a Bash script designed to provide superuser-level permission management and security tools for Linux systems, including Termux and Kali NetHunter environments. It is intended to be run as root and will automatically re-execute itself with `sudo` if not already running with root privileges.

## Features
- **Root Access Enforcement:** Ensures the script is always run as root, prompting for sudo if necessary.
- **Permission Management:**
  - Change file or directory ownership (single or recursively).
  - Modify file or directory permissions (single or recursively).
  - View current permissions of files or directories.
- **Auto-Run Setup:** Easily add scripts to system startup using `/etc/init.d/` and `update-rc.d`.
- **Security Tools:**
  - Scan for world-writable files.
  - Find SUID/SGID files.
  - List open network ports.
- **Kali NetHunter/Termux Environment Setup:**
  - Install Kali NetHunter or Termux environments.
- **Metasploit Framework Management:**
  - Install Metasploit Framework.
  - Launch Metasploit Console.
  - Search for exploits from the console.
- **Kali NetHunter Tools Management:**
  - Install the full Kali NetHunter toolset.
  - List, search, and run available tools or exploits.
- **Advanced Features:**
  - Grant root/superuser permissions to users and ensure `su` binaries exist in all required paths.
  - Grant superuser/root for mobile devices (Android/Tablet/Termux/NetHunter).
  - Settings & UI configuration (default terminal, permissions, owner, UI theme).
  - Enhanced colored UI and performance improvements.

## Usage
Run the script with:

```bash
sudo ./permissions_manager.sh
```

Follow the interactive menu to select the desired operation. Each menu option will guide you through the required steps for managing permissions, setting up environments, or running security tools.

**Note:** Some features (like installing packages or modifying system files) require an active internet connection and root privileges.

---

## Example: Setting Up Security Tools in Termux

If you want to set up a full security environment in Termux, you can use the following steps (or adapt the script for your own setup):

```bash
# Set up environment directories
BASE_DIR="$HOME/security_tools"
TOOLS_DIR="$BASE_DIR/tools"
WORKSPACE_DIR="$BASE_DIR/workspace"

mkdir -p "$TOOLS_DIR/metasploit" "$TOOLS_DIR/fatrat" "$TOOLS_DIR/kraken" "$TOOLS_DIR/exploits" "$TOOLS_DIR/wordlists" "$WORKSPACE_DIR"

# Install Metasploit
cd "$TOOLS_DIR/metasploit"
wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate
chmod +x msfupdate
./msfupdate

# Install TheFatRat
cd "$TOOLS_DIR/fatrat"
git clone https://github.com/Screetsec/TheFatRat.git .
chmod +x setup.sh
./setup.sh

# Install Kraken
cd "$TOOLS_DIR/kraken"
git clone https://github.com/jasonxtn/kraken.git .
pip3 install -r requirements.txt

# Set up Python environment
pkg install -y python-pip
pip3 install --upgrade pip
pip3 install virtualenv
cd "$BASE_DIR"
virtualenv venv
source venv/bin/activate
pip3 install requests beautifulsoup4 colorama prompt_toolkit
```

---

## Environment Configuration Example

Add these lines to your shell profile or a config file to quickly access your tools:

```bash
export SECURITY_TOOLS_HOME="$HOME/security_tools"
export PATH="$PATH:$SECURITY_TOOLS_HOME/bin"

alias msfconsole="cd $SECURITY_TOOLS_HOME/tools/metasploit && ./msfconsole"
alias fatrat="cd $SECURITY_TOOLS_HOME/tools/fatrat && ./fatrat"
alias kraken="cd $SECURITY_TOOLS_HOME/tools/kraken && python kraken.py"
```

---

## Logging and Permissions
- All actions and errors are logged for auditing.
- Permissions and ownership are set for all created directories and binaries.

---

## Troubleshooting
- Ensure you have root privileges for all advanced features.
- For Termux, run `termux-setup-storage` before using the script.
- If you encounter issues with missing dependencies, rerun the setup or install the required packages manually.

---

## License
This project is provided for educational and authorized security testing purposes only. Use responsibly and with permission.
