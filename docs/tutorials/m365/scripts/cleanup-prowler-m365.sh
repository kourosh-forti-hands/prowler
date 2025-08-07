#!/bin/bash

# Cleanup script for Prowler M365 authentication
# This script removes all resources created by the setup scripts

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared functions
source "$SCRIPT_DIR/setup-prowler-m365.sh"

# Banner
echo -e "${RED}${BOLD}================================================${NC}"
echo -e "${RED}${BOLD}   Prowler M365 - Cleanup Script                ${NC}"
echo -e "${RED}${BOLD}================================================${NC}"
echo
echo -e "${YELLOW}WARNING: This script will remove:${NC}"
echo "- App registration(s) named 'Prowler Security Scanner'"
echo "- Associated service principals"
echo "- All client secrets"
echo "- Exchange Online role groups (if created)"
echo "- Local credential files"
echo
echo -e "${RED}This action cannot be undone!${NC}"
echo

# Function to remove app registration
remove_app_registration() {
    local tenant_id=$1
    local app_name=$2
    
    print_info "Searching for app registration: $app_name"
    
    local result=$($POWERSHELL_CMD -Command "
        try {
            Connect-MgGraph -TenantId '$tenant_id' -Scopes 'Application.ReadWrite.All' -NoWelcome
            
            # Find the app
            \$apps = Get-MgApplication -Filter \"displayName eq '$app_name'\"
            
            if (\$apps.Count -eq 0) {
                Write-Output 'NOT_FOUND'
            } else {
                foreach (\$app in \$apps) {
                    # Remove service principal first
                    \$sp = Get-MgServicePrincipal -Filter \"appId eq '\$(\$app.AppId)'\" -ErrorAction SilentlyContinue
                    if (\$sp) {
                        Remove-MgServicePrincipal -ServicePrincipalId \$sp.Id
                        Write-Host \"Removed service principal: \$(\$sp.Id)\"
                    }
                    
                    # Remove app registration
                    Remove-MgApplication -ApplicationId \$app.Id
                    Write-Host \"Removed app registration: \$(\$app.DisplayName) (\$(\$app.AppId))\"
                }
                Write-Output 'SUCCESS'
            }
            
            Disconnect-MgGraph | Out-Null
        } catch {
            Write-Output \"ERROR: \$_\"
        }
    " 2>&1)
    
    if [[ "$result" == *"SUCCESS"* ]]; then
        print_success "App registration(s) removed successfully"
        return 0
    elif [[ "$result" == *"NOT_FOUND"* ]]; then
        print_warning "No app registrations found with name: $app_name"
        return 0
    else
        print_error "Failed to remove app registration"
        echo "$result"
        return 1
    fi
}

# Function to remove Exchange Online resources
remove_exchange_resources() {
    local admin_email=$1
    
    print_info "Checking for Exchange Online resources..."
    
    $POWERSHELL_CMD -Command "
        try {
            Import-Module ExchangeOnlineManagement
            Connect-ExchangeOnline -UserPrincipalName '$admin_email' -ShowBanner:\$false
            
            # Remove role group
            \$roleGroup = Get-RoleGroup -Identity 'Prowler Security Scanner' -ErrorAction SilentlyContinue
            if (\$roleGroup) {
                Remove-RoleGroup -Identity 'Prowler Security Scanner' -Confirm:\$false
                Write-Host 'Removed Exchange Online role group'
            } else {
                Write-Host 'No Exchange Online role group found'
            }
            
            Disconnect-ExchangeOnline -Confirm:\$false
        } catch {
            Write-Warning \"Could not connect to Exchange Online: \$_\"
        }
    " 2>&1
}

# Function to remove credential files
remove_credential_files() {
    print_header "Removing Local Credential Files"
    
    local files_removed=0
    
    # Remove single tenant config
    if [[ -f "$SCRIPT_DIR/prowler-m365-config.env" ]]; then
        rm -f "$SCRIPT_DIR/prowler-m365-config.env"
        print_success "Removed prowler-m365-config.env"
        files_removed=$((files_removed + 1))
    fi
    
    # Remove multi-tenant config
    if [[ -f "$SCRIPT_DIR/prowler-m365-multi-tenant.env" ]]; then
        rm -f "$SCRIPT_DIR/prowler-m365-multi-tenant.env"
        print_success "Removed prowler-m365-multi-tenant.env"
        files_removed=$((files_removed + 1))
    fi
    
    # Remove tenant-specific configs
    if [[ -d "$SCRIPT_DIR/tenant-configs" ]]; then
        local tenant_files=$(find "$SCRIPT_DIR/tenant-configs" -name "prowler-m365-*.env" 2>/dev/null | wc -l)
        if [[ $tenant_files -gt 0 ]]; then
            rm -rf "$SCRIPT_DIR/tenant-configs"
            print_success "Removed $tenant_files tenant configuration file(s)"
            files_removed=$((files_removed + tenant_files))
        fi
    fi
    
    if [[ $files_removed -eq 0 ]]; then
        print_info "No credential files found to remove"
    else
        print_success "Removed $files_removed credential file(s)"
    fi
}

# Main cleanup process
main() {
    # Check for credential files
    local config_files=()
    
    if [[ -f "$SCRIPT_DIR/prowler-m365-config.env" ]]; then
        config_files+=("$SCRIPT_DIR/prowler-m365-config.env")
    fi
    
    if [[ -f "$SCRIPT_DIR/prowler-m365-multi-tenant.env" ]]; then
        config_files+=("$SCRIPT_DIR/prowler-m365-multi-tenant.env")
    fi
    
    if [[ -d "$SCRIPT_DIR/tenant-configs" ]]; then
        while IFS= read -r -d '' file; do
            config_files+=("$file")
        done < <(find "$SCRIPT_DIR/tenant-configs" -name "prowler-m365-*.env" -print0 2>/dev/null)
    fi
    
    if [[ ${#config_files[@]} -eq 0 ]]; then
        print_warning "No configuration files found"
        read -p "Do you want to manually specify a tenant to clean up? (y/n): " MANUAL_CLEANUP
        
        if [[ "$MANUAL_CLEANUP" =~ ^[Yy]$ ]]; then
            read -p "Enter tenant domain or ID: " TENANT_INPUT
            read -p "Enter admin email: " ADMIN_EMAIL
            
            # Try to resolve tenant ID
            if [[ "$TENANT_INPUT" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
                TENANT_ID="$TENANT_INPUT"
            else
                TENANT_ID=$(get_tenant_id_from_domain "$TENANT_INPUT")
                if [[ -z "$TENANT_ID" ]]; then
                    print_error "Could not resolve tenant ID"
                    exit 1
                fi
            fi
            
            # Proceed with cleanup
            remove_app_registration "$TENANT_ID" "$M365_APP_NAME"
            remove_exchange_resources "$ADMIN_EMAIL"
        fi
    else
        print_info "Found ${#config_files[@]} configuration file(s)"
        echo
        
        # Process each configuration
        for config_file in "${config_files[@]}"; do
            print_header "Processing: $(basename "$config_file")"
            
            # Source the configuration
            source "$config_file"
            
            local tenant_id="${M365_TENANT_ID:-$AZURE_TENANT_ID}"
            local app_name="$M365_APP_NAME"
            
            if [[ -z "$tenant_id" ]]; then
                print_warning "No tenant ID found in $config_file"
                continue
            fi
            
            print_info "Tenant ID: $tenant_id"
            read -p "Remove resources for this tenant? (y/n): " CONFIRM
            
            if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
                # Get admin email for Exchange cleanup
                read -p "Enter admin email for Exchange cleanup (or press Enter to skip): " ADMIN_EMAIL
                
                # Remove app registration
                remove_app_registration "$tenant_id" "$app_name"
                
                # Remove Exchange resources if email provided
                if [[ -n "$ADMIN_EMAIL" ]] && validate_email "$ADMIN_EMAIL"; then
                    remove_exchange_resources "$ADMIN_EMAIL"
                fi
            else
                print_info "Skipping tenant"
            fi
            echo
        done
        
        # Remove credential files
        read -p "Remove all local credential files? (y/n): " REMOVE_FILES
        if [[ "$REMOVE_FILES" =~ ^[Yy]$ ]]; then
            remove_credential_files
        fi
    fi
    
    print_header "Cleanup Complete"
    print_success "All specified resources have been removed"
    echo
    print_info "Note: If you created any custom configurations or integrated with"
    print_info "other systems, you may need to update or remove those manually."
}

# Confirm before proceeding
read -p "Are you sure you want to remove all Prowler M365 resources? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    print_info "Cleanup cancelled"
    exit 0
fi

# Check system compatibility
if ! check_system_compatibility; then
    print_error "System compatibility check failed"
    exit 1
fi

# Run main cleanup
main