# Trustedinstaller
#!/data/data/com.termux/files/usr/bin/bash

# Script metadata
SCRIPT_VERSION="1.0"
CURRENT_DATE="2025-05-07 13:01:28"
CURRENT_USER="mathew-sudo"

# Directory structure
BASE_DIR="$HOME/security_tools"
WORKSPACE_DIR="$BASE_DIR/workspace"
TOOLS_DIR="$BASE_DIR/tools"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Function to check root
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

# Function to set up basic environment
setup_environment() {
    echo -e "${GREEN}[+] Setting up basic environment...${NC}"
    
    # Update package repositories
    pkg update -y && pkg upgrade -y
    
    # Install basic requirements
    pkg install -y \
        python \
        python2 \
        git \
        wget \
        curl \
        nodejs \
        php \
        ruby \
        make \
        clang \
        openssh \
        nmap \
        hydra
}

# Function to create directory structure
create_directories() {
    echo -e "${GREEN}[+] Creating directory structure...${NC}"
    mkdir -p "$WORKSPACE_DIR"
    mkdir -p "$TOOLS_DIR"/{metasploit,fatrat,kraken,exploits,wordlists}
}

# Function to install Metasploit Framework
install_metasploit() {
    echo -e "${GREEN}[+] Installing Metasploit Framework...${NC}"
    cd "$TOOLS_DIR/metasploit"
    wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate
    chmod +x msfupdate
    ./msfupdate
}

# Function to install custom tools
install_custom_tools() {
    echo -e "${GREEN}[+] Installing additional security tools...${NC}"
    
    # TheFatRat (Modified for Termux compatibility)
    cd "$TOOLS_DIR/fatrat"
    git clone https://github.com/Screetsec/TheFatRat.git .
    chmod +x setup.sh
    ./setup.sh
    
    # Kraken
    cd "$TOOLS_DIR/kraken"
    git clone https://github.com/jasonxtn/kraken.git .
    pip3 install -r requirements.txt
}

# Function to set up Python environment
setup_python_env() {
    echo -e "${GREEN}[+] Setting up Python environment...${NC}"
    pkg install -y python-pip
    pip3 install --upgrade pip
    pip3 install virtualenv
    
    # Create virtual environment
    cd "$BASE_DIR"
    virtualenv venv
    source venv/bin/activate
    
    # Install Python packages
    pip3 install \
        requests \
        beautifulsoup4 \
        colorama \
        prompt_toolkit
}

# Function to install additional packages
install_packages() {
    echo -e "${GREEN}[+] Installing additional packages...${NC}"
    pkg install -y \
        7zip \
        unrar \
        unzip \
        tar \
        wget \
        curl \
        git \
        python \
        python2 \
        php \
        ruby \
        nodejs \
        vim \
        nano \
        nmap
}

# Main execution
main() {
    echo -e "${GREEN}[*] Starting security tools installation script v${SCRIPT_VERSION}${NC}"
    echo -e "${GREEN}[*] Current user: ${CURRENT_USER}${NC}"
    echo -e "${GREEN}[*] Date: ${CURRENT_DATE}${NC}"
    
    # Create termux properties directory
    mkdir -p ~/.termux
    
    # Setup storage access
    termux-setup-storage
    
    # Run installation functions
    setup_environment
    create_directories
    setup_python_env
    install_packages
    install_metasploit
    install_custom_tools
    
    echo -e "${GREEN}[+] Installation completed successfully!${NC}"
    echo -e "${GREEN}[+] Tools installed in: ${BASE_DIR}${NC}"
}

# Execute main function
main

#!/data/data/com.termux/files/usr/bin/bash

# Configuration settings
export SECURITY_TOOLS_HOME="$HOME/security_tools"
export PATH="$PATH:$SECURITY_TOOLS_HOME/bin"

# Tool-specific configurations
export METASPLOIT_DATABASE="postgresql"
export FATRAT_ENCODING="UTF-8"
export KRAKEN_DEBUG="false"

# Custom aliases
alias msfconsole="cd $SECURITY_TOOLS_HOME/tools/metasploit && ./msfconsole"
alias fatrat="cd $SECURITY_TOOLS_HOME/tools/fatrat && ./fatrat"
alias kraken="cd $SECURITY_TOOLS_HOME/tools/kraken && python kraken.py"
chmod +x setup_termux_security.sh config.sh

bash ./setup_termux_security.sh

source config.sh

#!/data/data/com.termux/files/usr/bin/bash

# Script Metadata
SCRIPT_VERSION="2.0"
TIMESTAMP="2025-05-08 03:06:13"
CURRENT_USER="mathew-sudo"
INSTALLER_ID="trustedinstaller_${CURRENT_USER}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Base directories
BASE_DIR="$HOME/security_environment"
TOOLS_DIR="$BASE_DIR/tools"
WORKSPACE_DIR="$BASE_DIR/workspace"
TEMP_DIR="$BASE_DIR/temp"

# Log configuration
LOG_FILE="$BASE_DIR/setup_log_$(date +%Y%m%d_%H%M%S).log"

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}" | tee -a "$LOG_FILE"
}

# Function to check and create directories
create_directory_structure() {
    log_message "${BLUE}" "Creating directory structure..."
    
    local dirs=(
        "$BASE_DIR"
        "$TOOLS_DIR"
        "$WORKSPACE_DIR"
        "$TEMP_DIR"
        "$BASE_DIR/frameworks"
        "$BASE_DIR/exploits"
        "$BASE_DIR/bruteforce"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        log_message "${GREEN}" "Created directory: $dir"
    done
}

# Function to setup package repositories
setup_repositories() {
    log_message "${BLUE}" "Setting up package repositories..."
    
    pkg update -y
    pkg upgrade -y
    
    # Add required repositories
    echo "deb https://termux.org/packages/ stable main" >> $PREFIX/etc/apt/sources.list
    apt update
}

# Function to install base packages
install_base_packages() {
    log_message "${BLUE}" "Installing base packages..."
    
    local packages=(
        "7zip-standalone"
        "7zip-rar"
        "python"
        "python2"
        "git"
        "wget"
        "curl"
        "openssh"
        "iptables"
        "dnsmasq"
        "bash-completion"
        "build-essential"
        "cmake"
        "pkg-config"
    )
    
    for package in "${packages[@]}"; do
        log_message "${YELLOW}" "Installing $package..."
        pkg install -y "$package" || log_message "${RED}" "Failed to install $package"
    done
}

# Function to setup Python environment
setup_python_environment() {
    log_message "${BLUE}" "Setting up Python environment..."
    
    pip install --upgrade pip
    pip install virtualenv
    
    # Create virtual environment
    python -m venv "$BASE_DIR/venv"
    source "$BASE_DIR/venv/bin/activate"
    
    # Install Python packages
    pip install requests beautifulsoup4 colorama prompt_toolkit
}

# Function to install security frameworks
install_security_frameworks() {
    log_message "${BLUE}" "Installing security frameworks..."
    
    # TheFatRat Installation
    cd "$TOOLS_DIR"
    git clone https://github.com/Screetsec/TheFatRat.git
    cd TheFatRat
    chmod +x setup.sh
    ./setup.sh
    
    # Kraken Installation
    cd "$TOOLS_DIR"
    git clone https://github.com/jasonxtn/kraken.git
    cd kraken
    pip install -r requirements.txt
    chmod +x chk_tools
    
    # Bruteforce tools
    pkg install -y hydra ncrack john
}

# Function to setup permissions
setup_permissions() {
    log_message "${BLUE}" "Setting up permissions..."
    
    # Set proper permissions for tools directory
    chmod -R 750 "$TOOLS_DIR"
    chmod -R 750 "$WORKSPACE_DIR"
    
    # Create permission configuration file
    cat > "$BASE_DIR/permissions.conf" << EOF
OWNER=$CURRENT_USER
INSTALLER_ID=$INSTALLER_ID
TIMESTAMP=$TIMESTAMP
PERMISSION_LEVEL=superuser+trustedinstaller
EOF
}

# Function to create environment configuration
create_environment_config() {
    log_message "${BLUE}" "Creating environment configuration..."
    
    cat > "$BASE_DIR/environment.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
export SECURITY_ENV_HOME="$BASE_DIR"
export PATH="\$PATH:$TOOLS_DIR/bin"
export PYTHONPATH="\$PYTHONPATH:$BASE_DIR/venv/lib/python3.9/site-packages"
export TOOLS_DIR="$TOOLS_DIR"
export WORKSPACE_DIR="$WORKSPACE_DIR"
EOF

    chmod +x "$BASE_DIR/environment.sh"
}

# Main execution function
main() {
    log_message "${GREEN}" "Starting advanced Termux setup script v${SCRIPT_VERSION}"
    log_message "${GREEN}" "Current user: ${CURRENT_USER}"
    log_message "${GREEN}" "Timestamp: ${TIMESTAMP}"
    
    # Execute setup steps
    create_directory_structure
    setup_repositories
    install_base_packages
    setup_python_environment
    install_security_frameworks
    setup_permissions
    create_environment_config
    
    log_message "${GREEN}" "Setup completed successfully!"
    log_message "${GREEN}" "Please source the environment configuration:"
    echo -e "${YELLOW}source $BASE_DIR/environment.sh${NC}"
}

# Execute main function with error handling
if main; then
    exit 0
else
    log_message "${RED}" "Setup failed! Check the log file: $LOG_FILE"
    exit 1
fi

#!/data/data/com.termux/files/usr/bin/bash

# Environment Configuration
export SECURITY_ENV_HOME="$HOME/security_environment"
export PATH="$PATH:$SECURITY_ENV_HOME/tools/bin"
export PYTHONPATH="$PYTHONPATH:$SECURITY_ENV_HOME/venv/lib/python3.9/site-packages"

# Tool-specific configurations
export FATRAT_HOME="$SECURITY_ENV_HOME/tools/TheFatRat"
export KRAKEN_HOME="$SECURITY_ENV_HOME/tools/kraken"

# Aliases for quick access
alias fatrat="cd $FATRAT_HOME && ./fatrat"
alias kraken="cd $KRAKEN_HOME && python kraken.py"

# Custom security functions
check_permissions() {
    if [ "$EUID" -eq 0 ]; then
        echo "Running with root privileges"
    else
        echo "Running with user privileges"
    fi
}

# Initialize environment
echo "Security environment initialized for user: $(whoami)"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

chmod +x advanced_termux_setup.sh environment.sh
./advanced_termux_setup.sh
source ~/security_environment/environment.sh
#!/data/data/com.termux/files/usr/bin/bash

# Environment Configuration
export SECURITY_ENV_HOME="$HOME/security_environment"
export PATH="$PATH:$SECURITY_ENV_HOME/tools/bin"
export PYTHONPATH="$PYTHONPATH:$SECURITY_ENV_HOME/venv/lib/python3.9/site-packages"

# Tool-specific configurations
export FATRAT_HOME="$SECURITY_ENV_HOME/tools/TheFatRat"
export KRAKEN_HOME="$SECURITY_ENV_HOME/tools/kraken"

# Aliases for quick access
alias fatrat="cd $FATRAT_HOME && ./fatrat"
alias kraken="cd $KRAKEN_HOME && python kraken.py"

# Custom security functions
check_permissions() {
    if [ "$EUID" -eq 0 ]; then
        echo "Running with root privileges"
    else
        echo "Running with user privileges"
    fi
}

# Initialize environment
echo "Security environment initialized for user: $(whoami)"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
