#!/bin/bash

# All-in-one setup script for Prowler M365 authentication - Multi-Tenant Version
# This script handles:
# 1. Installation of PowerShell Core (if needed)
# 2. Installation of required PowerShell modules
# 3. Complete Prowler M365 authentication setup for multiple tenants
#
# IMPORTANT NOTES:
# - You will need Global Administrator or Application Administrator role in each tenant
# - Each tenant will require separate admin consent
# - Credentials will be saved for each tenant separately

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared functions
source "$SCRIPT_DIR/setup-prowler-m365.sh"

# Array to store tenant configurations
declare -a TENANT_CONFIGS

# Banner
echo -e "${BLUE}${BOLD}========================================================${NC}"
echo -e "${BLUE}${BOLD}   Prowler for M365 - Complete Setup (Multi-Tenant)    ${NC}"
echo -e "${BLUE}${BOLD}========================================================${NC}"
echo
echo -e "${YELLOW}IMPORTANT PERMISSION REQUIREMENTS:${NC}"
echo -e "- You need ${BOLD}Global Administrator${NC} or ${BOLD}Application Administrator${NC} role in each tenant"
echo -e "- For automatic admin consent, you need ${BOLD}Global Administrator${NC} role"
echo -e "- Each tenant will be configured separately"
echo
echo -e "${GREEN}This script will guide you through setting up multiple M365 tenants.${NC}"
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

# Step 4: Collect tenant information
print_header "Step 3: Collecting Tenant Information"

echo "Let's collect information about the M365 tenants you want to configure."
echo

TENANT_COUNT=0
while true; do
    TENANT_COUNT=$((TENANT_COUNT + 1))
    
    echo -e "${BLUE}${BOLD}=== Tenant #$TENANT_COUNT ===${NC}"
    echo
    
    # Get tenant domain
    while true; do
        read -p "Enter tenant domain (e.g., contoso.onmicrosoft.com): " TENANT_DOMAIN
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
            read -p "Enter tenant ID manually (or press Enter to try another domain): " MANUAL_TENANT_ID
            if [[ -n "$MANUAL_TENANT_ID" ]]; then
                TENANT_ID="$MANUAL_TENANT_ID"
                break
            fi
        fi
    done
    
    # Get admin email for this tenant
    while true; do
        read -p "Enter admin email for this tenant: " ADMIN_EMAIL
        if validate_email "$ADMIN_EMAIL"; then
            break
        else
            print_error "Invalid email address format"
        fi
    done
    
    # Store tenant configuration
    TENANT_CONFIGS+=("$TENANT_DOMAIN|$TENANT_ID|$ADMIN_EMAIL")
    
    echo
    read -p "Do you want to add another tenant? (y/n): " ADD_MORE
    if [[ ! "$ADD_MORE" =~ ^[Yy]$ ]]; then
        break
    fi
    echo
done

# Display summary
print_header "Tenant Configuration Summary"
echo "You have configured ${#TENANT_CONFIGS[@]} tenant(s):"
echo
for i in "${!TENANT_CONFIGS[@]}"; do
    IFS='|' read -r domain tenant_id email <<< "${TENANT_CONFIGS[$i]}"
    echo "$((i+1)). Domain: $domain"
    echo "   Tenant ID: $tenant_id"
    echo "   Admin: $email"
    echo
done

read -p "Is this correct? (y/n): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    print_info "Setup cancelled. Please run the script again."
    exit 0
fi

# Step 5: Process each tenant
print_header "Step 4: Configuring Each Tenant"

# Create directory for multi-tenant configs
mkdir -p "$SCRIPT_DIR/tenant-configs"

for i in "${!TENANT_CONFIGS[@]}"; do
    IFS='|' read -r TENANT_DOMAIN TENANT_ID ADMIN_EMAIL <<< "${TENANT_CONFIGS[$i]}"
    
    echo
    echo -e "${BLUE}${BOLD}=== Processing Tenant: $TENANT_DOMAIN ===${NC}"
    echo
    
    # Check admin roles
    print_info "Checking admin permissions for $ADMIN_EMAIL..."
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
        print_warning "You don't have required admin roles in this tenant"
        read -p "Do you want to skip this tenant? (y/n): " SKIP_TENANT
        if [[ "$SKIP_TENANT" =~ ^[Yy]$ ]]; then
            print_info "Skipping tenant: $TENANT_DOMAIN"
            continue
        fi
    fi
    
    # Authenticate to M365
    print_info "Authenticating to tenant: $TENANT_DOMAIN"
    $POWERSHELL_CMD -Command "
        Connect-MgGraph -TenantId '$TENANT_ID' -Scopes 'Application.ReadWrite.All', 'User.Read.All', 'RoleManagement.Read.All' -NoWelcome
        Write-Host 'Successfully connected to Microsoft Graph'
    " || {
        print_error "Failed to connect to Microsoft Graph for tenant: $TENANT_DOMAIN"
        continue
    }
    
    # Create app registration
    print_info "Creating app registration in tenant: $TENANT_DOMAIN"
    APP_ID=$(create_app_registration "$TENANT_ID" "$M365_APP_NAME")
    if [[ -z "$APP_ID" ]]; then
        print_error "Failed to create app registration in tenant: $TENANT_DOMAIN"
        continue
    fi
    
    # Create client secret
    print_info "Creating client secret..."
    CLIENT_SECRET=$(create_client_secret "$TENANT_ID" "$APP_ID")
    if [[ -z "$CLIENT_SECRET" ]]; then
        print_error "Failed to create client secret in tenant: $TENANT_DOMAIN"
        continue
    fi
    
    # Grant admin consent
    grant_admin_consent "$TENANT_ID" "$APP_ID" "$HAS_GLOBAL_ADMIN"
    
    # Test authentication
    print_info "Testing authentication..."
    if test_m365_authentication "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET"; then
        print_success "Authentication test successful for tenant: $TENANT_DOMAIN"
    else
        print_warning "Authentication test failed for tenant: $TENANT_DOMAIN"
    fi
    
    # Save tenant-specific credentials
    TENANT_CONFIG_FILE="$SCRIPT_DIR/tenant-configs/prowler-m365-$TENANT_DOMAIN.env"
    save_credentials "$TENANT_ID" "$APP_ID" "$CLIENT_SECRET" "$TENANT_CONFIG_FILE"
    
    # Disconnect from current tenant
    $POWERSHELL_CMD -Command "Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null" 2>/dev/null
    
    print_success "Configuration completed for tenant: $TENANT_DOMAIN"
done

# Step 6: Create consolidated configuration file
print_header "Step 5: Creating Consolidated Configuration"

MULTI_CONFIG_FILE="$SCRIPT_DIR/prowler-m365-multi-tenant.env"
cat > "$MULTI_CONFIG_FILE" << EOF
# Prowler M365 Multi-Tenant Authentication Configuration
# Generated on: $(date)
# IMPORTANT: Keep this file secure and do not commit to version control

# Number of configured tenants
export M365_TENANT_COUNT=${#TENANT_CONFIGS[@]}

EOF

# Add each tenant's configuration
SUCCESSFUL_TENANTS=0
for i in "${!TENANT_CONFIGS[@]}"; do
    IFS='|' read -r TENANT_DOMAIN TENANT_ID ADMIN_EMAIL <<< "${TENANT_CONFIGS[$i]}"
    TENANT_CONFIG_FILE="$SCRIPT_DIR/tenant-configs/prowler-m365-$TENANT_DOMAIN.env"
    
    if [[ -f "$TENANT_CONFIG_FILE" ]]; then
        echo "# Tenant $((i+1)): $TENANT_DOMAIN" >> "$MULTI_CONFIG_FILE"
        echo "export M365_TENANT_${i}_DOMAIN=\"$TENANT_DOMAIN\"" >> "$MULTI_CONFIG_FILE"
        
        # Extract credentials from tenant config file
        source "$TENANT_CONFIG_FILE"
        echo "export M365_TENANT_${i}_ID=\"$M365_TENANT_ID\"" >> "$MULTI_CONFIG_FILE"
        echo "export M365_TENANT_${i}_CLIENT_ID=\"$M365_CLIENT_ID\"" >> "$MULTI_CONFIG_FILE"
        echo "export M365_TENANT_${i}_CLIENT_SECRET=\"$M365_CLIENT_SECRET\"" >> "$MULTI_CONFIG_FILE"
        echo "" >> "$MULTI_CONFIG_FILE"
        
        SUCCESSFUL_TENANTS=$((SUCCESSFUL_TENANTS + 1))
    fi
done

chmod 600 "$MULTI_CONFIG_FILE"
print_success "Multi-tenant configuration saved to: $MULTI_CONFIG_FILE"

# Step 7: Display summary
print_header "Multi-Tenant Setup Complete"

echo -e "${GREEN}${BOLD}Successfully configured $SUCCESSFUL_TENANTS out of ${#TENANT_CONFIGS[@]} tenant(s)${NC}"
echo

if [[ $SUCCESSFUL_TENANTS -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}Configuration files created:${NC}"
    echo "- Multi-tenant config: $MULTI_CONFIG_FILE"
    echo "- Individual configs: $SCRIPT_DIR/tenant-configs/"
    echo
    echo -e "${YELLOW}To use these credentials with Prowler:${NC}"
    echo -e "1. ${BLUE}For all tenants:${NC}"
    echo -e "   ${GREEN}source $MULTI_CONFIG_FILE${NC}"
    echo -e "   ${GREEN}# Then use tenant-specific variables in your scripts${NC}"
    echo
    echo -e "2. ${BLUE}For a specific tenant:${NC}"
    echo -e "   ${GREEN}source $SCRIPT_DIR/tenant-configs/prowler-m365-DOMAIN.env${NC}"
    echo -e "   ${GREEN}prowler m365 --sp-env-auth${NC}"
    echo
fi

echo -e "${RED}${BOLD}⚠️  SECURITY WARNING ⚠️${NC}"
echo -e "${RED}The configuration files contain sensitive credentials!${NC}"
echo -e "${RED}Store them securely and never commit to version control.${NC}"
echo

print_success "Multi-tenant M365 authentication setup completed!"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Test credentials for each tenant individually"
echo "2. If you encounter issues, run: ./troubleshoot-m365-auth.sh"
echo "3. To remove all created resources, run: ./cleanup-prowler-m365.sh"
echo