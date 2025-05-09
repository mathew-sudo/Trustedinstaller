#!/bin/bash

# Permissions Manager Script
# This script provides superuser-level permission management and security tools.

# Function to check if the script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root. Please switch to the root user and try again."
        exit 1
    fi
}

# Function to manage file permissions
manage_permissions() {
    echo "Enter the file or directory path:"
    read path

    echo "Choose an action:"
    echo "1. Change ownership"
    echo "2. Modify permissions"
    echo "3. View current permissions"
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

# Function to set up Kali NetHunter or Termux environment
setup_kali_nethunter_termux() {
    echo "Setting up environment for Kali NetHunter or Termux..."

    echo "Choose an option:"
    echo "1. Install Kali NetHunter"
    echo "2. Install Termux"
    read env_choice

    case $env_choice in
        1)
            echo "Installing Kali NetHunter..."
            apt update && apt install -y kali-linux-default
            echo "Kali NetHunter installed successfully."
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

# Main menu
main_menu() {
    check_root

    echo "Permissions Manager"
    echo "1. Manage Permissions"
    echo "2. Set Up Auto-Run"
    echo "3. Security Tools"
    echo "4. Set Up Kali NetHunter/Termux"
    echo "5. Manage Metasploit/Exploits"
    echo "6. Manage Kali NetHunter Tools/Exploits"
    echo "7. Exit"
    read choice

    case $choice in
        1)
            manage_permissions
            ;;
        2)
            setup_autorun
            ;;
        3)
            security_tools
            ;;
        4)
            setup_kali_nethunter_termux
            ;;
        5)
            setup_metasploit
            ;;
        6)
            setup_kali_nethunter_tools
            ;;
        7)
            exit 0
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
}

# Run the main menu
main_menu
