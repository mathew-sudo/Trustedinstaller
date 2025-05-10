#!/bin/bash

# If not running as root, re-execute this script with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Script requires root. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Permissions Manager Script
# This script provides superuser-level permission management and security tools.

# Function to check if the script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root. Please switch to the root user and try again."
        exit 1
    fi
}

# Enhanced manage_permissions function to include recursive permission changes
manage_permissions() {
    echo "Enter the file or directory path:"
    read path

    if [ ! -e "$path" ]; then
        echo "Error: Path does not exist."
        return
    fi

    echo "Choose an action:"
    echo "1. Change ownership"
    echo "2. Modify permissions"
    echo "3. View current permissions"
    echo "4. Change ownership recursively"
    echo "5. Modify permissions recursively"
    read action

    case $action in
        1)
            echo "Enter the new owner (user:group):"
            read owner
            chown $owner "$path"
            echo "Ownership changed to $owner."
            ;;
        2)
            echo "Enter the new permissions (e.g., 755):"
            read perms
            chmod $perms "$path"
            echo "Permissions changed to $perms."
            ;;
        3)
            ls -l "$path"
            ;;
        4)
            echo "Enter the new owner (user:group):"
            read owner
            chown -R $owner "$path"
            echo "Ownership recursively changed to $owner."
            ;;
        5)
            echo "Enter the new permissions (e.g., 755):"
            read perms
            chmod -R $perms "$path"
            echo "Permissions recursively changed to $perms."
            ;;
        *)
            echo "Invalid action."
            ;;
    esac
}

# Function to set up auto-run for a script
setup_autorun() {
    echo "Enter the script path to auto-run on startup:"
    read script_path

    if [ -f "$script_path" ]; then
        cp "$script_path" /etc/init.d/
        chmod +x /etc/init.d/$(basename "$script_path")
        update-rc.d $(basename "$script_path") defaults
        echo "Script added to auto-run."
    else
        echo "Script not found."
    fi
}

# Function to perform basic security checks
security_tools() {
    echo "Running basic security checks..."
    echo "1. Checking for world-writable files..."
    find / -type f -perm -o+w 2>/dev/null

    echo "2. Checking for SUID/SGID files..."
    find / -perm /6000 -type f 2>/dev/null

    echo "3. Checking for open ports..."
    netstat -tuln
}

# Function to set up Kali NetHunter or Termux environment with UI
setup_kali_nethunter_termux() {
    echo "Setting up environment for Kali NetHunter or Termux..."
    echo "Choose an option:"
    echo "1. Install Kali NetHunter (Full UI)"
    echo "2. Install Termux"
    read env_choice

    case $env_choice in
        1)
            echo "Installing Kali NetHunter (Full UI)..."
            apt update && apt install -y kali-linux-default kali-desktop-xfce tightvncserver
            echo "Kali NetHunter base and XFCE desktop installed."
            echo "Setting up VNC server for graphical UI..."
            vncserver :1
            echo "To access the Kali NetHunter UI, connect your VNC client to localhost:5901."
            ;;
        2)
            echo "Installing Termux..."
            apt update && apt install -y termux
            echo "Termux installed successfully."
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
}

# Function to install and manage Metasploit Framework
setup_metasploit() {
    echo "Setting up Metasploit Framework..."

    echo "Choose an option:"
    echo "1. Install Metasploit Framework"
    echo "2. Launch Metasploit Console"
    echo "3. Search for Exploits"
    read metasploit_choice

    case $metasploit_choice in
        1)
            echo "Installing Metasploit Framework..."
            apt update && apt install -y metasploit-framework
            echo "Metasploit Framework installed successfully."
            ;;
        2)
            echo "Launching Metasploit Console..."
            msfconsole
            ;;
        3)
            echo "Enter the search term for exploits:"
            read search_term
            msfconsole -q -x "search $search_term; exit"
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
}

# Function to install and manage Kali NetHunter tools and exploits
setup_kali_nethunter_tools() {
    echo "Setting up Kali NetHunter tools and exploits..."
    echo "Choose an option:"
    echo "1. Install Full Kali NetHunter Toolset"
    echo "2. List Available Tools"
    echo "3. Search for a Tool or Exploit"
    echo "4. Run a Tool or Exploit"
    read nethunter_choice

    case $nethunter_choice in
        1)
            echo "Installing full Kali NetHunter toolset..."
            apt update && apt install -y kali-linux-everything
            echo "Full Kali NetHunter toolset installed successfully."
            ;;
        2)
            echo "Listing all available tools..."
            dpkg -l | grep kali
            ;;
        3)
            echo "Enter the search term for a tool or exploit:"
            read search_term
            apt-cache search $search_term
            ;;
        4)
            echo "Enter the name of the tool or exploit to run:"
            read tool_name
            $tool_name
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
}

# Function to float (run) up to 6 terminal windows
float_windows() {
    local max_windows=6
    local current_windows
    # Try to count open xterm/gnome-terminal/konsole windows
    current_windows=$(pgrep -c -f 'xterm|gnome-terminal|konsole')
    if [ "$current_windows" -ge "$max_windows" ]; then
        echo "Maximum of $max_windows floating windows already running."
        return
    fi
    echo "Choose terminal to float (1: xterm, 2: gnome-terminal, 3: konsole):"
    read term_choice
    case $term_choice in
        1)
            if command -v xterm >/dev/null 2>&1; then
                xterm &
            else
                echo "xterm not installed."
            fi
            ;;
        2)
            if command -v gnome-terminal >/dev/null 2>&1; then
                gnome-terminal &
            else
                echo "gnome-terminal not installed."
            fi
            ;;
        3)
            if command -v konsole >/dev/null 2>&1; then
                konsole &
            else
                echo "konsole not installed."
            fi
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
}

# Function to run bruteforce.ng hull
bruteforce_ng_hull() {
    echo "Running bruteforce.ng hull..."
    echo "Enter the target (e.g., IP or hostname):"
    read target
    echo "Enter the username to bruteforce (leave blank to skip):"
    read username
    echo "Enter the path to the password wordlist (e.g., /usr/share/wordlists/rockyou.txt):"
    read wordlist
    echo "Enter the service to bruteforce (e.g., ssh, ftp, http):"
    read service

    if [ -z "$target" ] || [ -z "$wordlist" ] || [ -z "$service" ]; then
        echo "Target, wordlist, and service are required."
        return
    fi

    if ! command -v hydra >/dev/null 2>&1; then
        echo "Hydra is not installed. Installing hydra..."
        apt update && apt install -y hydra
    fi

    if [ -n "$username" ]; then
        echo "Starting bruteforce attack on $service://$target with username $username..."
        hydra -l "$username" -P "$wordlist" "$target" "$service"
    else
        echo "Starting bruteforce attack on $service://$target with usernames from wordlist..."
        hydra -L "$wordlist" -P "$wordlist" "$target" "$service"
    fi
}

# Function to launch Console Ninja Engine
console_ninja_engine() {
    echo "Launching Console Ninja Engine..."
    echo "--- Console Ninja Help Menu ---"
    echo "1. Manage Permissions: Change, view, or set permissions recursively."
    echo "2. Set Up Auto-Run: Add scripts to system startup."
    echo "3. Security Tools: Scan for world-writable files, SUID/SGID files, open ports."
    echo "4. Set Up Kali NetHunter/Termux: Install Kali NetHunter (with UI) or Termux."
    echo "5. Manage Metasploit/Exploits: Install, launch, or search Metasploit."
    echo "6. Manage Kali NetHunter Tools/Exploits: Install, list, search, or run tools."
    echo "7. Float up to 6 Windows: Launch up to 6 terminal windows."
    echo "8. Exit: Quit the Permissions Manager."
    echo "9. Run bruteforce.ng hull: Launch a bruteforce attack using hydra."
    echo "10. Console Ninja Engine: Show this help menu."
    echo "-------------------------------"
}

# Helper for colored output
color_echo() {
    local color="$1"; shift
    case $color in
        red)    echo -e "\033[31m$*\033[0m" ;;
        green)  echo -e "\033[32m$*\033[0m" ;;
        yellow) echo -e "\033[33m$*\033[0m" ;;
        blue)   echo -e "\033[34m$*\033[0m" ;;
        magenta)echo -e "\033[35m$*\033[0m" ;;
        cyan)   echo -e "\033[36m$*\033[0m" ;;
        bold)   echo -e "\033[1m$*\033[0m" ;;
        *)      echo "$*" ;;
    esac
}

# Banner for UI
show_banner() {
    clear
    color_echo cyan "==============================="
    color_echo bold "   Permissions Manager UI"
    color_echo cyan "==============================="
}

# Settings and UI config file path
default_settings_file="/etc/permissions_manager.conf"

# Function to load settings from config file
load_settings() {
    if [ -f "$default_settings_file" ]; then
        source "$default_settings_file"
    fi
}

# Function to save settings to config file
save_settings() {
    echo "# Permissions Manager Settings" > "$default_settings_file"
    echo "DEFAULT_TERMINAL=\"$DEFAULT_TERMINAL\"" >> "$default_settings_file"
    echo "DEFAULT_PERMS=\"$DEFAULT_PERMS\"" >> "$default_settings_file"
    echo "DEFAULT_OWNER=\"$DEFAULT_OWNER\"" >> "$default_settings_file"
    echo "UI_THEME=\"$UI_THEME\"" >> "$default_settings_file"
    chmod 600 "$default_settings_file"
}

# Function to configure UI and settings
settings_ui_config() {
    echo "--- Settings & UI Config ---"
    echo "1. Set Default Terminal (current: ${DEFAULT_TERMINAL:-xterm})"
    echo "2. Set Default Permissions (current: ${DEFAULT_PERMS:-755})"
    echo "3. Set Default Owner (current: ${DEFAULT_OWNER:-root:root})"
    echo "4. Set UI Theme (current: ${UI_THEME:-default})"
    echo "5. Save Settings"
    echo "6. Back to Main Menu"
    read -p "Choose an option: " settings_choice
    case $settings_choice in
        1)
            read -p "Enter default terminal (xterm/gnome-terminal/konsole): " DEFAULT_TERMINAL
            ;;
        2)
            read -p "Enter default permissions (e.g., 755): " DEFAULT_PERMS
            ;;
        3)
            read -p "Enter default owner (user:group): " DEFAULT_OWNER
            ;;
        4)
            read -p "Enter UI theme (default/dark/light): " UI_THEME
            ;;
        5)
            save_settings
            echo "Settings saved."
            ;;
        6)
            return
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
    settings_ui_config
}

# Function to grant root/superuser permission to a user and ensure su binaries exist
grant_root_superuser() {
    echo "Enter the username to grant root/superuser permissions to:"
    read username
    # ...existing code for grant_root_superuser...
}

# Function to grant superuser/root on Android mobile phone or tablet (Termux/NetHunter)
grant_mobile_superuser() {
    echo "Granting superuser/root access for mobile device (Android/Termux/NetHunter)..."
    # ...existing code for grant_mobile_superuser...
}

# Load settings at script start
load_settings

# Main menu with UI improvements and all options
main_menu() {
    check_root
    while true; do
        show_banner
        color_echo yellow "Select an option:"
        echo "1. Manage Permissions"
        echo "2. Set Up Auto-Run"
        echo "3. Security Tools"
        echo "4. Set Up Kali NetHunter/Termux"
        echo "5. Manage Metasploit/Exploits"
        echo "6. Manage Kali NetHunter Tools/Exploits"
        echo "7. Float up to 6 Windows"
        echo "8. Exit"
        echo "9. Run bruteforce.ng hull"
        echo "10. Console Ninja Engine (Help)"
        echo "11. Grant Root/Superuser Permission to User & Ensure su Binaries"
        echo "12. Grant Superuser/Root for Mobile Device (Android/Tablet)"
        echo "13. Settings & UI Config"
        read -p "Enter choice [1-13]: " choice
        case $choice in
            1) manage_permissions ;;
            2) setup_autorun ;;
            3) security_tools ;;
            4) setup_kali_nethunter_termux ;;
            5) setup_metasploit ;;
            6) setup_kali_nethunter_tools ;;
            7) float_windows ;;
            8) exit 0 ;;
            9) bruteforce_ng_hull ;;
            10) console_ninja_engine ;;
            11) grant_root_superuser ;;
            12) grant_mobile_superuser ;;
            13) settings_ui_config ;;
            *) color_echo red "Invalid choice." ; sleep 1 ;;
        esac
    done
}

# Run the main menu
main_menu
