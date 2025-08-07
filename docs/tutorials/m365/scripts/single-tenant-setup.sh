#!/bin/bash

# Core setup script for Prowler M365 authentication - Single Tenant
# This script assumes prerequisites are already installed
# For automatic prerequisite installation, use all-in-one-setup.sh

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared functions
source "$SCRIPT_DIR/setup-prowler-m365.sh"

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -d, --domain DOMAIN        M365 tenant domain (e.g., contoso.onmicrosoft.com)"
    echo "  -t, --tenant-id ID         Tenant ID (optional if domain is provided)"
    echo "  -e, --email EMAIL          Admin email address"
    echo "  -n, --app-name NAME        App registration name (default: Prowler Security Scanner)"
    echo "  -o, --output FILE          Output file for credentials (default: prowler-m365-config.env)"
    echo "  -s, --skip-exchange        Skip Exchange Online configuration"
    echo "  -h, --help                 Display this help message"
    echo
    echo "Example:"
    echo "  $0 --domain contoso.onmicrosoft.com --email admin@contoso.com"
    exit 1
}

# Parse command line arguments
TENANT_DOMAIN=""
TENANT_ID=""
ADMIN_EMAIL=""
OUTPUT_FILE="prowler-m365-config.env"
SKIP_EXCHANGE=false
APP_NAME="$M365_APP_NAME"

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            TENANT_DOMAIN="$2"
            shift 2
            ;;
        -t|--tenant-id)
            TENANT_ID="$2"
            shift 2
            ;;
        -e|--email)
            ADMIN_EMAIL="$2"
            shift 2
            ;;
        -n|--app-name)
            APP_NAME="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -s|--skip-exchange)
            SKIP_EXCHANGE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Banner
echo -e "${BLUE}${BOLD}================================================${NC}"
echo -e "${BLUE}${BOLD}   Prowler M365 Setup - Single Tenant Core     ${NC}"
echo -e "${BLUE}${BOLD}================================================${NC}"
echo

# Validate inputs
if [[ -z "$TENANT_DOMAIN" ]] && [[ -z "$TENANT_ID" ]]; then
    print_error "Either tenant domain or tenant ID must be provided"
    usage
fi

if [[ -z "$ADMIN_EMAIL" ]]; then
    print_error "Admin email is required"
    usage
fi

if ! validate_email "$ADMIN_EMAIL"; then
    print_error "Invalid email address format: $ADMIN_EMAIL"
    exit 1
fi

# Check system compatibility
if ! check_system_compatibility; then
    print_error "System compatibility check failed"
    print_info "Run all-in-one-setup.sh to install prerequisites automatically"
    exit 1
fi

# Resolve tenant ID if not provided
if [[ -z "$TENANT_ID" ]]; then
    print_info "Resolving tenant ID from domain: $TENANT_DOMAIN"
    TENANT_ID=$(get_tenant_id_from_domain "$TENANT_DOMAIN")
    if [[ -z "$TENANT_ID" ]]; then
        print_error "Could not resolve tenant ID from domain: $TENANT_DOMAIN"
        exit 1
    fi
    print_success "Tenant ID resolved: $TENANT_ID"
fi

# Check admin roles
print_header "Checking Admin Permissions"

ROLE_CHECK=$(check_admin_roles "$ADMIN_EMAIL")
HAS_GLOBAL_ADMIN=false
HAS_APP_ADMIN=false

if [[ "$ROLE_CHECK" == *"GLOBAL_ADMIN:True"* ]]; then
    HAS_GLOBAL_ADMIN=true
    print_success "Global Administrator role detected"
fi

if [[ "$ROLE_CHECK" == *"APP_ADMIN:True"* ]]; then
    HAS_APP_ADMIN=true
    print_success "Application Administrator role detected"
fi

if [[ "$HAS_GLOBAL_ADMIN" == "false" ]] && [[ "$HAS_APP_ADMIN" == "false" ]]; then
    print_warning "No admin roles detected. You may need assistance from an administrator."
fi

# Connect to Microsoft Graph
print_header "Connecting to Microsoft Graph"

print_info "Authenticating as $ADMIN_EMAIL..."
$POWERSHELL_CMD -Command "
    try {
        Connect-MgGraph -TenantId '$TENANT_ID' -Scopes 'Application.ReadWrite.All', 'User.Read.All', 'RoleManagement.Read.All' -NoWelcome
        Write-Host 'Successfully connected to Microsoft Graph'
    } catch {
        Write-Error \"Failed to connect: \$_\"
        exit 1
    }
" || {
    print_error "Failed to connect to Microsoft Graph"
    exit 1
}

# Create app registration
print_header "Creating App Registration"

APP_ID=$(create_app_registration "$TENANT_ID" "$APP_NAME")
if [[ -z "$APP_ID" ]]; then
    print_error "Failed to create app registration"
    exit 1
fi

# Create client secret
print_header "Creating Client Secret"

CLIENT_SECRET=$(create_client_secret "$TENANT_ID" "$APP_ID")
if [[ -z "$CLIENT_SECRET" ]]; then
    print_error "Failed to create client secret"
    exit 1
fi

# Grant admin consent
grant_admin_consent "$TENANT_ID" "$APP_ID" "$HAS_GLOBAL_ADMIN"

# Configure Exchange Online if not skipped
if [[ "$SKIP_EXCHANGE" == "false" ]]; then
    print_header "Exchange Online Configuration"
    
    read -p "Configure Exchange Online permissions? (y/n): " CONFIGURE_EXCHANGE
    if [[ "$CONFIGURE_EXCHANGE" =~ ^[Yy]$ ]]; then
        configure_exchange_online "$TENANT_ID" "$APP_ID" "$ADMIN_EMAIL"
    fi
fi

# Test authentication
print_header "Testing Authentication"

if test_m365_authentication "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET"; then
    print_success "Authentication test passed"
else
    print_warning "Authentication test failed - credentials may still work"
fi

# Save credentials
save_credentials "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET" "$OUTPUT_FILE"

# Display summary
display_credentials "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET"

# Cleanup
print_info "Disconnecting from Microsoft Graph..."
$POWERSHELL_CMD -Command "Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null" 2>/dev/null

print_success "Setup completed successfully!"