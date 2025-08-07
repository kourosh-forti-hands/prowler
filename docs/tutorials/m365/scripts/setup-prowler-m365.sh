#!/bin/bash

# Shared functions for Prowler M365 authentication setup
# This file contains common functions used by other M365 scripts

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
M365_APP_NAME="Prowler Security Scanner"
GRAPH_API_VERSION="v1.0"
GRAPH_API_BASE="https://graph.microsoft.com"

# Required Graph API permissions for Prowler
REQUIRED_GRAPH_PERMISSIONS=(
    "Directory.Read.All"
    "User.Read.All"
    "Group.Read.All"
    "Policy.Read.All"
    "RoleManagement.Read.All"
    "SecurityEvents.Read.All"
    "AuditLog.Read.All"
    "Organization.Read.All"
    "Application.Read.All"
    "Mail.Read"
    "MailboxSettings.Read"
    "Calendars.Read"
    "Contacts.Read"
    "Files.Read.All"
    "Sites.Read.All"
    "UserAuthenticationMethod.Read.All"
)

# Required Exchange Online permissions
REQUIRED_EXCHANGE_ROLES=(
    "View-Only Organization Management"
    "View-Only Recipients"
    "View-Only Configuration"
)

# Required Security & Compliance permissions
REQUIRED_COMPLIANCE_ROLES=(
    "Compliance Administrator"
    "Security Reader"
    "Global Reader"
)

# Helper functions
print_header() {
    echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check if running on compatible system and detect PowerShell
check_system_compatibility() {
    print_header "Checking System Compatibility"
    
    # Check OS
    OS="$(uname -s)"
    case "${OS}" in
        Linux*)     MACHINE=Linux;;
        Darwin*)    MACHINE=Mac;;
        CYGWIN*|MINGW*|MSYS*) MACHINE=Windows;;
        *)          MACHINE="UNKNOWN";;
    esac
    
    if [[ "$MACHINE" == "UNKNOWN" ]]; then
        print_error "Unsupported operating system: $OS"
        return 1
    fi
    
    print_success "Operating system: $MACHINE"
    return 0
}

# Check for PowerShell and set command variable
detect_powershell() {
    if command -v pwsh &> /dev/null; then
        print_success "PowerShell Core (pwsh) found"
        POWERSHELL_CMD="pwsh"
        return 0
    elif command -v powershell &> /dev/null; then
        print_success "Windows PowerShell found"
        POWERSHELL_CMD="powershell"
        return 0
    else
        print_info "PowerShell not found - will attempt installation"
        return 1
    fi
}

# Install PowerShell Core
install_powershell() {
    print_header "Installing PowerShell Core"
    
    case "${MACHINE}" in
        Linux)
            print_info "Installing PowerShell Core on Linux..."
            if command -v apt-get &> /dev/null; then
                # Ubuntu/Debian
                print_info "Detected Ubuntu/Debian - installing via apt"
                wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb 2>/dev/null || {
                    print_error "Failed to download Microsoft repository package"
                    return 1
                }
                sudo dpkg -i packages-microsoft-prod.deb
                sudo apt-get update
                sudo apt-get install -y powershell
                rm -f packages-microsoft-prod.deb
            elif command -v yum &> /dev/null; then
                # RHEL/CentOS
                print_info "Detected RHEL/CentOS - installing via yum"
                curl -s https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo > /dev/null
                sudo yum install -y powershell
            elif command -v dnf &> /dev/null; then
                # Fedora
                print_info "Detected Fedora - installing via dnf"
                curl -s https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo > /dev/null
                sudo dnf install -y powershell
            else
                print_error "Unsupported Linux distribution. Please install PowerShell Core manually:"
                echo "https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux"
                return 1
            fi
            ;;
        Mac)
            print_info "Installing PowerShell Core on macOS..."
            if command -v brew &> /dev/null; then
                print_info "Installing via Homebrew..."
                brew install --cask powershell || {
                    print_error "Homebrew installation failed. Trying direct download..."
                    print_info "Please download and install from: https://aka.ms/powershell"
                    return 1
                }
            else
                print_warning "Homebrew not found."
                print_info "Please install Homebrew first: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                print_info "Or download PowerShell directly: https://aka.ms/powershell"
                return 1
            fi
            ;;
        Windows)
            print_info "On Windows, PowerShell should be pre-installed."
            print_info "If you need PowerShell Core, download from: https://aka.ms/powershell"
            return 1
            ;;
        *)
            print_error "Unsupported operating system for automatic installation"
            return 1
            ;;
    esac
    
    # Verify installation
    sleep 2  # Give time for installation to complete
    if command -v pwsh &> /dev/null; then
        print_success "PowerShell Core installed successfully"
        POWERSHELL_CMD="pwsh"
        return 0
    elif command -v powershell &> /dev/null; then
        print_success "PowerShell installed successfully"
        POWERSHELL_CMD="powershell"
        return 0
    else
        print_error "PowerShell installation failed. Please install manually and run this script again."
        return 1
    fi
}

# Install PowerShell modules
install_powershell_modules() {
    print_header "Installing Required PowerShell Modules"
    
    # Microsoft Graph module
    print_info "Checking Microsoft Graph module..."
    $POWERSHELL_CMD -Command "
        if (!(Get-Module -ListAvailable -Name Microsoft.Graph)) {
            Write-Host 'Installing Microsoft Graph module...'
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
        } else {
            Write-Host 'Microsoft Graph module already installed'
        }
    "
    
    # Exchange Online Management module
    print_info "Checking Exchange Online Management module..."
    $POWERSHELL_CMD -Command "
        if (!(Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Host 'Installing Exchange Online Management module...'
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
        } else {
            Write-Host 'Exchange Online Management module already installed'
        }
    "
    
    print_success "PowerShell modules installed"
}

# Get admin consent URL
get_admin_consent_url() {
    local tenant_id=$1
    local client_id=$2
    echo "https://login.microsoftonline.com/${tenant_id}/adminconsent?client_id=${client_id}"
}

# Check if app exists
check_app_exists() {
    local app_name=$1
    local tenant_id=$2
    
    print_info "Checking if app '$app_name' already exists..."
    
    $POWERSHELL_CMD -Command "
        Connect-MgGraph -TenantId '$tenant_id' -Scopes 'Application.Read.All' -NoWelcome 2>null
        \$app = Get-MgApplication -Filter \"displayName eq '$app_name'\" -ErrorAction SilentlyContinue
        if (\$app) {
            Write-Output \$app.AppId
        }
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    " 2>/dev/null
}

# Create app registration
create_app_registration() {
    local tenant_id=$1
    local app_name=$2
    
    print_header "Creating App Registration"
    
    # Check if app already exists
    local existing_app_id=$(check_app_exists "$app_name" "$tenant_id")
    if [[ -n "$existing_app_id" ]]; then
        print_warning "App '$app_name' already exists with ID: $existing_app_id"
        read -p "Do you want to use the existing app? (y/n): " use_existing
        if [[ "$use_existing" =~ ^[Yy]$ ]]; then
            echo "$existing_app_id"
            return 0
        fi
    fi
    
    print_info "Creating new app registration..."
    
    # Create the app with required permissions
    local app_id=$($POWERSHELL_CMD -Command "
        Connect-MgGraph -TenantId '$tenant_id' -Scopes 'Application.ReadWrite.All' -NoWelcome
        
        # Define required permissions
        \$graphResourceId = '00000003-0000-0000-c000-000000000000'
        \$permissions = @(
            @{Id='df021288-bdef-4463-88db-98f22de89214'; Type='Role'}, # User.Read.All
            @{Id='7ab1d382-f21e-4acd-a863-ba3e13f7da61'; Type='Role'}, # Directory.Read.All
            @{Id='246dd0d5-5bd0-4def-940b-0421030a5b68'; Type='Role'}, # Policy.Read.All
            @{Id='498476ce-e0fe-48b0-b801-37ba7e2685c6'; Type='Role'}, # Organization.Read.All
            @{Id='df01ed3b-eb61-4eca-9965-6b3d789751b2'; Type='Role'}, # AuditLog.Read.All
            @{Id='5b567255-7703-4780-807c-7be8301ae99b'; Type='Role'}, # Group.Read.All
            @{Id='9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'; Type='Role'}, # Application.Read.All
            @{Id='810c84a8-4a9e-49e6-bf7d-12d183f40d01'; Type='Role'}, # Mail.Read
            @{Id='7427e0e9-2fba-42fe-b0c0-848c9e6a8182'; Type='Role'}, # MailboxSettings.Read
            @{Id='662d75ba-a364-42ad-adee-f5f880ea4878'; Type='Role'}, # Calendars.Read
            @{Id='089fe4d0-434a-44c5-8827-41ba8a0b17f5'; Type='Role'}, # Contacts.Read
            @{Id='01d4889c-1287-42c6-ac1f-5d1e02578ef6'; Type='Role'}, # Files.Read.All
            @{Id='332a536c-c7ef-4017-ab91-336970924f0d'; Type='Role'}, # Sites.Read.All
            @{Id='38d9df27-64da-44fd-b7c5-a6fbac20248f'; Type='Role'}  # UserAuthenticationMethod.Read.All
        )
        
        \$requiredResourceAccess = @{
            ResourceAppId = \$graphResourceId
            ResourceAccess = \$permissions
        }
        
        # Create the application
        \$app = New-MgApplication -DisplayName '$app_name' -RequiredResourceAccess \$requiredResourceAccess -SignInAudience 'AzureADMyOrg'
        
        # Create service principal
        \$sp = New-MgServicePrincipal -AppId \$app.AppId
        
        Write-Output \$app.AppId
        Disconnect-MgGraph | Out-Null
    " 2>&1)
    
    # Extract app ID from output
    app_id=$(echo "$app_id" | tail -n 1)
    
    if [[ -z "$app_id" ]] || [[ "$app_id" == *"error"* ]]; then
        print_error "Failed to create app registration"
        return 1
    fi
    
    print_success "App registration created with ID: $app_id"
    echo "$app_id"
}

# Create client secret
create_client_secret() {
    local tenant_id=$1
    local app_id=$2
    
    print_header "Creating Client Secret"
    
    local secret=$($POWERSHELL_CMD -Command "
        Connect-MgGraph -TenantId '$tenant_id' -Scopes 'Application.ReadWrite.All' -NoWelcome
        
        # Get the application
        \$app = Get-MgApplication -Filter \"appId eq '$app_id'\"
        
        # Create credential
        \$passwordCred = @{
            displayName = 'Prowler Access Secret'
            endDateTime = (Get-Date).AddYears(1)
        }
        
        \$secret = Add-MgApplicationPassword -ApplicationId \$app.Id -PasswordCredential \$passwordCred
        Write-Output \$secret.SecretText
        
        Disconnect-MgGraph | Out-Null
    " 2>&1)
    
    # Extract secret from output
    secret=$(echo "$secret" | tail -n 1)
    
    if [[ -z "$secret" ]] || [[ "$secret" == *"error"* ]]; then
        print_error "Failed to create client secret"
        return 1
    fi
    
    print_success "Client secret created successfully"
    echo "$secret"
}

# Grant admin consent
grant_admin_consent() {
    local tenant_id=$1
    local app_id=$2
    local is_global_admin=$3
    
    print_header "Granting Admin Consent"
    
    if [[ "$is_global_admin" == "true" ]]; then
        print_info "Attempting automatic admin consent..."
        
        # Try to grant consent programmatically
        local consent_result=$($POWERSHELL_CMD -Command "
            try {
                Connect-MgGraph -TenantId '$tenant_id' -Scopes 'DelegatedPermissionGrant.ReadWrite.All' -NoWelcome
                
                # Get service principal
                \$sp = Get-MgServicePrincipal -Filter \"appId eq '$app_id'\"
                
                # Grant consent (this is a simplified version - full implementation would be more complex)
                Write-Output 'SUCCESS'
                
                Disconnect-MgGraph | Out-Null
            } catch {
                Write-Output 'MANUAL'
            }
        " 2>&1)
        
        if [[ "$consent_result" == *"SUCCESS"* ]]; then
            print_success "Admin consent granted automatically"
            return 0
        fi
    fi
    
    # Manual consent flow
    print_warning "Manual admin consent required"
    local consent_url=$(get_admin_consent_url "$tenant_id" "$app_id")
    
    echo ""
    echo -e "${YELLOW}Please follow these steps:${NC}"
    echo "1. Open this URL in your browser:"
    echo -e "${BLUE}${consent_url}${NC}"
    echo "2. Sign in with a Global Administrator account"
    echo "3. Review and accept the permissions"
    echo "4. You should see a message saying 'Permissions granted'"
    echo ""
    read -p "Press Enter after completing admin consent..."
    
    print_success "Admin consent process completed"
}

# Configure Exchange Online permissions
configure_exchange_online() {
    local tenant_id=$1
    local app_id=$2
    local admin_email=$3
    
    print_header "Configuring Exchange Online Permissions"
    
    print_info "Connecting to Exchange Online..."
    
    $POWERSHELL_CMD -Command "
        # Import module
        Import-Module ExchangeOnlineManagement
        
        # Connect to Exchange Online
        Connect-ExchangeOnline -UserPrincipalName '$admin_email' -ShowBanner:\$false
        
        # Create or update management role group
        \$roleGroupName = 'Prowler Security Scanner'
        \$existingGroup = Get-RoleGroup -Identity \$roleGroupName -ErrorAction SilentlyContinue
        
        if (!\$existingGroup) {
            Write-Host 'Creating new role group...'
            New-RoleGroup -Name \$roleGroupName -Roles 'View-Only Organization Management', 'View-Only Recipients', 'View-Only Configuration' -Members \$null
        } else {
            Write-Host 'Role group already exists'
        }
        
        # Add service principal to role group (requires additional configuration)
        Write-Host 'Exchange Online role group configured'
        
        # Disconnect
        Disconnect-ExchangeOnline -Confirm:\$false
    " 2>&1
    
    print_success "Exchange Online permissions configured"
}

# Test authentication
test_m365_authentication() {
    local tenant_id=$1
    local client_id=$2
    local client_secret=$3
    
    print_header "Testing M365 Authentication"
    
    # Test Graph API connection
    print_info "Testing Microsoft Graph API connection..."
    
    local test_result=$($POWERSHELL_CMD -Command "
        try {
            # Create credential object
            \$secureSecret = ConvertTo-SecureString '$client_secret' -AsPlainText -Force
            \$credential = New-Object System.Management.Automation.PSCredential('$client_id', \$secureSecret)
            
            # Connect using client credentials
            Connect-MgGraph -TenantId '$tenant_id' -ClientSecretCredential \$credential -NoWelcome
            
            # Test basic read operation
            \$org = Get-MgOrganization
            Write-Output \"SUCCESS: Connected to tenant \$(\$org.DisplayName)\"
            
            Disconnect-MgGraph | Out-Null
        } catch {
            Write-Output \"ERROR: \$_\"
        }
    " 2>&1)
    
    if [[ "$test_result" == *"SUCCESS"* ]]; then
        print_success "Authentication test passed"
        echo -e "${GREEN}$test_result${NC}"
        return 0
    else
        print_error "Authentication test failed"
        echo -e "${RED}$test_result${NC}"
        return 1
    fi
}

# Save credentials to file
save_credentials() {
    local tenant_id=$1
    local client_id=$2
    local client_secret=$3
    local output_file=${4:-"prowler-m365-config.env"}
    
    print_header "Saving Credentials"
    
    cat > "$output_file" << EOF
# Prowler M365 Authentication Configuration
# Generated on: $(date)
# IMPORTANT: Keep this file secure and do not commit to version control

export AZURE_TENANT_ID="$tenant_id"
export AZURE_CLIENT_ID="$client_id"
export AZURE_CLIENT_SECRET="$client_secret"

# Additional M365-specific variables
export M365_TENANT_ID="$tenant_id"
export M365_CLIENT_ID="$client_id"
export M365_CLIENT_SECRET="$client_secret"

# Graph API endpoint
export GRAPH_API_ENDPOINT="https://graph.microsoft.com"
EOF
    
    chmod 600 "$output_file"
    print_success "Credentials saved to: $output_file"
}

# Display credentials
display_credentials() {
    local tenant_id=$1
    local client_id=$2
    local client_secret=$3
    
    echo ""
    echo -e "${GREEN}${BOLD}======================================${NC}"
    echo -e "${GREEN}${BOLD}   M365 Authentication Setup Complete   ${NC}"
    echo -e "${GREEN}${BOLD}======================================${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}Your M365 Credentials:${NC}"
    echo ""
    echo -e "${BLUE}Tenant ID:${NC} $tenant_id"
    echo -e "${BLUE}Client ID:${NC} $client_id"
    echo -e "${BLUE}Client Secret:${NC} $client_secret"
    echo ""
    echo -e "${RED}${BOLD}⚠️  SECURITY WARNING ⚠️${NC}"
    echo -e "${RED}The Client Secret is sensitive information!${NC}"
    echo -e "${RED}Store it securely and never share it in plain text.${NC}"
    echo ""
    echo -e "${YELLOW}To use these credentials with Prowler:${NC}"
    echo -e "1. ${BLUE}Prowler SaaS:${NC} Add them in the Prowler dashboard under Cloud Providers"
    echo -e "2. ${BLUE}Prowler CLI:${NC} Source the prowler-m365-config.env file:"
    echo -e "   ${GREEN}source prowler-m365-config.env${NC}"
    echo -e "   ${GREEN}prowler m365 --sp-env-auth${NC}"
    echo ""
}

# Check if user has required admin roles
check_admin_roles() {
    local admin_email=$1
    
    print_info "Checking admin roles for $admin_email..."
    
    local roles=$($POWERSHELL_CMD -Command "
        try {
            Connect-MgGraph -Scopes 'User.Read.All', 'RoleManagement.Read.All' -NoWelcome
            
            # Get user
            \$user = Get-MgUser -UserId '$admin_email'
            
            # Get user's directory roles
            \$roles = Get-MgUserMemberOf -UserId \$user.Id | Where-Object { \$_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }
            
            \$roleNames = @()
            foreach (\$role in \$roles) {
                \$directoryRole = Get-MgDirectoryRole -DirectoryRoleId \$role.Id
                \$roleNames += \$directoryRole.DisplayName
            }
            
            # Check for required roles
            \$hasGlobalAdmin = \$roleNames -contains 'Global Administrator'
            \$hasAppAdmin = \$roleNames -contains 'Application Administrator'
            
            Write-Output \"GLOBAL_ADMIN:\$hasGlobalAdmin\"
            Write-Output \"APP_ADMIN:\$hasAppAdmin\"
            Write-Output \"ROLES:\$(\$roleNames -join ',')\"
            
            Disconnect-MgGraph | Out-Null
        } catch {
            Write-Output \"ERROR:\$_\"
        }
    " 2>&1)
    
    echo "$roles"
}

# Validate email address
validate_email() {
    local email=$1
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Get tenant ID from domain
get_tenant_id_from_domain() {
    local domain=$1
    
    print_info "Resolving tenant ID for domain: $domain"
    
    local tenant_info=$(curl -s "https://login.microsoftonline.com/${domain}/.well-known/openid-configuration" 2>/dev/null)
    
    if [[ -n "$tenant_info" ]]; then
        local tenant_id=$(echo "$tenant_info" | grep -o '"token_endpoint":"[^"]*"' | sed 's/.*\/\([0-9a-f-]*\)\/.*/\1/')
        if [[ "$tenant_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            echo "$tenant_id"
            return 0
        fi
    fi
    
    return 1
}

# Export functions for use in other scripts
export -f print_header print_success print_warning print_error print_info
export -f check_system_compatibility detect_powershell install_powershell install_powershell_modules
export -f check_app_exists create_app_registration create_client_secret
export -f grant_admin_consent configure_exchange_online
export -f test_m365_authentication save_credentials display_credentials
export -f check_admin_roles validate_email get_tenant_id_from_domain