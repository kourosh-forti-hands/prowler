#!/bin/bash

# All-in-one setup script for Prowler M365 authentication - Single Tenant Version
# This script handles:
# 1. Installation of PowerShell Core (if needed)
# 2. Installation of required PowerShell modules
# 3. Complete Prowler M365 authentication setup for a single tenant
#
# IMPORTANT NOTES:
# - You will need Global Administrator or Application Administrator role
# - If you don't have Global Administrator role, manual admin consent will be required
# - Exchange Online and Security & Compliance Center access requires additional admin roles

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared functions
source "$SCRIPT_DIR/setup-prowler-m365.sh"

# Banner
echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo -e "${BLUE}${BOLD}   Prowler for M365 - Complete Setup (Single Tenant)   ${NC}"
echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo
echo -e "${YELLOW}IMPORTANT PERMISSION REQUIREMENTS:${NC}"
echo -e "- You need ${BOLD}Global Administrator${NC} or ${BOLD}Application Administrator${NC} role"
echo -e "- For automatic admin consent, you need ${BOLD}Global Administrator${NC} role"
echo -e "- For Exchange Online access, you need ${BOLD}Exchange Administrator${NC} role"
echo -e "- For Security & Compliance, you need ${BOLD}Compliance Administrator${NC} role"
echo
echo -e "${GREEN}Don't worry if you don't have all these roles - the script will guide you through alternatives.${NC}"
echo
read -p "Press Enter to continue..."
echo

# Step 1: Check system compatibility
if ! check_system_compatibility; then
    print_error "System compatibility check failed."
    exit 1
fi

# Step 2: Check for PowerShell and install if needed
print_header "Step 1: Checking PowerShell Installation"

if ! detect_powershell; then
    print_warning "PowerShell not found. Attempting automatic installation..."
    
    if ! install_powershell; then
        print_error "Failed to install PowerShell automatically."
        echo
        print_info "Please install PowerShell manually:"
        case "${MACHINE}" in
            Mac)
                echo "  Option 1: brew install --cask powershell"
                echo "  Option 2: Download from https://aka.ms/powershell"
                ;;
            Linux)
                echo "  See: https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux"
                ;;
            *)
                echo "  Download from: https://aka.ms/powershell"
                ;;
        esac
        echo
        print_info "After installation, run this script again."
        exit 1
    fi
fi

# Step 3: Install PowerShell modules
print_header "Step 2: Installing Required PowerShell Modules"
install_powershell_modules

# Step 4: Get tenant information
print_header "Step 3: M365 Tenant Information"

echo "Please provide your M365 tenant information:"
echo

# Get tenant domain
while true; do
    read -p "Enter your M365 tenant domain (e.g., contoso.onmicrosoft.com): " TENANT_DOMAIN
    if [[ -z "$TENANT_DOMAIN" ]]; then
        print_error "Tenant domain cannot be empty"
        continue
    fi
    
    # Try to resolve tenant ID
    TENANT_ID=$(get_tenant_id_from_domain "$TENANT_DOMAIN")
    if [[ -n "$TENANT_ID" ]]; then
        print_success "Tenant ID resolved: $TENANT_ID"
        break
    else
        print_warning "Could not resolve tenant ID from domain."
        read -p "Enter your tenant ID manually (or press Enter to try another domain): " MANUAL_TENANT_ID
        if [[ -n "$MANUAL_TENANT_ID" ]]; then
            TENANT_ID="$MANUAL_TENANT_ID"
            break
        fi
    fi
done

# Get admin email
while true; do
    read -p "Enter your admin email address: " ADMIN_EMAIL
    if validate_email "$ADMIN_EMAIL"; then
        break
    else
        print_error "Invalid email address format"
    fi
done

# Step 5: Check admin roles
print_header "Step 4: Checking Admin Permissions"

print_info "Checking your admin roles..."
print_info "You may be prompted to sign in to Microsoft..."
echo

ROLE_CHECK=$(check_admin_roles "$ADMIN_EMAIL")

HAS_GLOBAL_ADMIN=false
HAS_APP_ADMIN=false

if [[ "$ROLE_CHECK" == *"GLOBAL_ADMIN:True"* ]]; then
    HAS_GLOBAL_ADMIN=true
    print_success "You have Global Administrator role"
fi

if [[ "$ROLE_CHECK" == *"APP_ADMIN:True"* ]]; then
    HAS_APP_ADMIN=true
    print_success "You have Application Administrator role"
fi

if [[ "$HAS_GLOBAL_ADMIN" == "false" ]] && [[ "$HAS_APP_ADMIN" == "false" ]]; then
    print_warning "You don't have Global Administrator or Application Administrator role"
    echo "You will need someone with these roles to:"
    echo "1. Create the app registration"
    echo "2. Grant admin consent"
    echo
    read -p "Do you want to continue anyway? (y/n): " continue_anyway
    if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
        print_info "Setup cancelled. Please run again with appropriate permissions."
        exit 0
    fi
fi

# Step 6: Authenticate to M365
print_header "Step 5: Authenticating to Microsoft 365"

print_info "Connecting to Microsoft Graph..."
print_info "Please sign in with your admin account when prompted..."
echo

# This will open a browser for interactive authentication
$POWERSHELL_CMD -Command "
    Connect-MgGraph -TenantId '$TENANT_ID' -Scopes 'Application.ReadWrite.All', 'User.Read.All', 'RoleManagement.Read.All' -NoWelcome
    Write-Host 'Successfully connected to Microsoft Graph'
    # Keep connection for subsequent operations
" || {
    print_error "Failed to connect to Microsoft Graph"
    exit 1
}

# Step 7: Create app registration
print_header "Step 6: Creating App Registration"

APP_ID=$(create_app_registration "$TENANT_ID" "$M365_APP_NAME")
if [[ -z "$APP_ID" ]]; then
    print_error "Failed to create app registration"
    exit 1
fi

print_success "App registration created/found with ID: $APP_ID"

# Step 8: Create client secret
print_header "Step 7: Creating Client Secret"

CLIENT_SECRET=$(create_client_secret "$TENANT_ID" "$APP_ID")
if [[ -z "$CLIENT_SECRET" ]]; then
    print_error "Failed to create client secret"
    exit 1
fi

print_success "Client secret created successfully"

# Step 9: Grant admin consent
grant_admin_consent "$TENANT_ID" "$APP_ID" "$HAS_GLOBAL_ADMIN"

# Step 10: Configure Exchange Online (optional)
print_header "Step 8: Exchange Online Configuration (Optional)"

echo "Exchange Online configuration provides additional email and mailbox security insights."
read -p "Do you want to configure Exchange Online permissions? (y/n): " CONFIGURE_EXCHANGE

if [[ "$CONFIGURE_EXCHANGE" =~ ^[Yy]$ ]]; then
    configure_exchange_online "$TENANT_ID" "$APP_ID" "$ADMIN_EMAIL"
else
    print_info "Skipping Exchange Online configuration"
fi

# Step 11: Test authentication
print_header "Step 9: Testing Authentication"

if test_m365_authentication "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET"; then
    print_success "Authentication test successful!"
else
    print_warning "Authentication test failed. The setup may still be successful."
    print_info "Try running the troubleshooting script if you encounter issues."
fi

# Step 12: Save credentials
save_credentials "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET"

# Step 13: Display summary
display_credentials "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET"

# Cleanup
print_info "Disconnecting from Microsoft Graph..."
$POWERSHELL_CMD -Command "Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null" 2>/dev/null

print_success "M365 authentication setup completed!"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Test the credentials with: source prowler-m365-config.env && prowler m365 --sp-env-auth"
echo "2. If you encounter issues, run: ./troubleshoot-m365-auth.sh"
echo "3. To remove all created resources, run: ./cleanup-prowler-m365.sh"
echo