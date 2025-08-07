#!/bin/bash

# Troubleshooting script for Prowler M365 authentication
# This script helps diagnose and fix common authentication issues

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared functions
source "$SCRIPT_DIR/setup-prowler-m365.sh"

# Diagnostic results
declare -A DIAGNOSTICS

# Banner
echo -e "${BLUE}${BOLD}================================================${NC}"
echo -e "${BLUE}${BOLD}   Prowler M365 - Troubleshooting Tool          ${NC}"
echo -e "${BLUE}${BOLD}================================================${NC}"
echo

# Function to check PowerShell installation
check_powershell_installation() {
    print_header "PowerShell Installation Check"
    
    local ps_found=false
    
    if command -v pwsh &> /dev/null; then
        local pwsh_version=$(pwsh -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null)
        print_success "PowerShell Core found: $pwsh_version"
        DIAGNOSTICS["powershell"]="PowerShell Core $pwsh_version"
        ps_found=true
    elif command -v powershell &> /dev/null; then
        local ps_version=$(powershell -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null)
        print_success "Windows PowerShell found: $ps_version"
        DIAGNOSTICS["powershell"]="Windows PowerShell $ps_version"
        ps_found=true
    else
        print_error "PowerShell not found"
        DIAGNOSTICS["powershell"]="Not installed"
        
        echo
        print_info "To install PowerShell Core:"
        case "$(uname -s)" in
            Linux*)
                echo "  Ubuntu/Debian: sudo apt-get install powershell"
                echo "  RHEL/CentOS: sudo yum install powershell"
                ;;
            Darwin*)
                echo "  macOS: brew install --cask powershell"
                ;;
            MINGW*|CYGWIN*|MSYS*)
                echo "  Windows: Download from https://aka.ms/powershell"
                ;;
        esac
    fi
    
    return $([ "$ps_found" = true ] && echo 0 || echo 1)
}

# Function to check PowerShell modules
check_powershell_modules() {
    print_header "PowerShell Modules Check"
    
    local modules_ok=true
    
    # Check Microsoft Graph module
    print_info "Checking Microsoft Graph module..."
    local graph_check=$($POWERSHELL_CMD -Command "
        if (Get-Module -ListAvailable -Name Microsoft.Graph) {
            \$module = Get-Module -ListAvailable -Name Microsoft.Graph | Select-Object -First 1
            Write-Output \"INSTALLED:\$(\$module.Version)\"
        } else {
            Write-Output 'NOT_INSTALLED'
        }
    " 2>&1)
    
    if [[ "$graph_check" == *"INSTALLED"* ]]; then
        local version=$(echo "$graph_check" | grep -o 'INSTALLED:.*' | cut -d: -f2)
        print_success "Microsoft Graph module: $version"
        DIAGNOSTICS["graph_module"]="Installed ($version)"
    else
        print_error "Microsoft Graph module not installed"
        DIAGNOSTICS["graph_module"]="Not installed"
        modules_ok=false
        
        echo "  To install: Install-Module Microsoft.Graph -Scope CurrentUser"
    fi
    
    # Check Exchange Online Management module
    print_info "Checking Exchange Online Management module..."
    local exo_check=$($POWERSHELL_CMD -Command "
        if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
            \$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Select-Object -First 1
            Write-Output \"INSTALLED:\$(\$module.Version)\"
        } else {
            Write-Output 'NOT_INSTALLED'
        }
    " 2>&1)
    
    if [[ "$exo_check" == *"INSTALLED"* ]]; then
        local version=$(echo "$exo_check" | grep -o 'INSTALLED:.*' | cut -d: -f2)
        print_success "Exchange Online Management module: $version"
        DIAGNOSTICS["exo_module"]="Installed ($version)"
    else
        print_warning "Exchange Online Management module not installed (optional)"
        DIAGNOSTICS["exo_module"]="Not installed (optional)"
        
        echo "  To install: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    fi
    
    return $([ "$modules_ok" = true ] && echo 0 || echo 1)
}

# Function to test tenant connectivity
test_tenant_connectivity() {
    local tenant_domain=$1
    
    print_header "Testing Tenant Connectivity"
    
    print_info "Testing connection to: $tenant_domain"
    
    # Test OpenID configuration endpoint
    local openid_url="https://login.microsoftonline.com/${tenant_domain}/.well-known/openid-configuration"
    local response=$(curl -s -w "\n%{http_code}" "$openid_url" 2>/dev/null)
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" == "200" ]]; then
        print_success "Tenant endpoint accessible"
        
        # Extract tenant ID
        local tenant_id=$(echo "$body" | grep -o '"token_endpoint":"[^"]*"' | sed 's/.*\/\([0-9a-f-]*\)\/.*/\1/')
        if [[ "$tenant_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            print_success "Tenant ID: $tenant_id"
            DIAGNOSTICS["tenant_id"]="$tenant_id"
            return 0
        else
            print_error "Could not extract tenant ID"
            return 1
        fi
    else
        print_error "Cannot reach tenant endpoint (HTTP $http_code)"
        DIAGNOSTICS["tenant_connectivity"]="Failed (HTTP $http_code)"
        return 1
    fi
}

# Function to check app registration
check_app_registration() {
    local tenant_id=$1
    local app_id=$2
    
    print_header "Checking App Registration"
    
    if [[ -z "$app_id" ]]; then
        print_warning "No app ID provided"
        return 1
    fi
    
    print_info "Checking app: $app_id"
    
    local app_check=$($POWERSHELL_CMD -Command "
        try {
            Connect-MgGraph -TenantId '$tenant_id' -Scopes 'Application.Read.All' -NoWelcome
            
            \$app = Get-MgApplication -Filter \"appId eq '$app_id'\" -ErrorAction Stop
            if (\$app) {
                Write-Output \"FOUND:\$(\$app.DisplayName)\"
                
                # Check required permissions
                \$graphPerms = \$app.RequiredResourceAccess | Where-Object { \$_.ResourceAppId -eq '00000003-0000-0000-c000-000000000000' }
                if (\$graphPerms) {
                    Write-Output \"PERMISSIONS:\$(\$graphPerms.ResourceAccess.Count)\"
                }
            } else {
                Write-Output 'NOT_FOUND'
            }
            
            Disconnect-MgGraph | Out-Null
        } catch {
            Write-Output \"ERROR:\$_\"
        }
    " 2>&1)
    
    if [[ "$app_check" == *"FOUND:"* ]]; then
        local app_name=$(echo "$app_check" | grep -o 'FOUND:.*' | cut -d: -f2)
        print_success "App registration found: $app_name"
        
        if [[ "$app_check" == *"PERMISSIONS:"* ]]; then
            local perm_count=$(echo "$app_check" | grep -o 'PERMISSIONS:.*' | cut -d: -f2)
            print_success "Graph API permissions configured: $perm_count"
        else
            print_warning "No Graph API permissions found"
        fi
        
        return 0
    else
        print_error "App registration not found"
        return 1
    fi
}

# Function to test authentication
test_authentication() {
    local tenant_id=$1
    local client_id=$2
    local client_secret=$3
    
    print_header "Testing Authentication"
    
    if [[ -z "$client_secret" ]]; then
        print_warning "No client secret provided - skipping authentication test"
        return 1
    fi
    
    print_info "Testing service principal authentication..."
    
    local auth_test=$($POWERSHELL_CMD -Command "
        try {
            \$secureSecret = ConvertTo-SecureString '$client_secret' -AsPlainText -Force
            \$credential = New-Object System.Management.Automation.PSCredential('$client_id', \$secureSecret)
            
            Connect-MgGraph -TenantId '$tenant_id' -ClientSecretCredential \$credential -NoWelcome
            
            # Test basic read
            \$org = Get-MgOrganization
            Write-Output \"SUCCESS:Connected to \$(\$org.DisplayName)\"
            
            # Check some permissions
            try {
                \$users = Get-MgUser -Top 1
                Write-Output 'PERM:User.Read.All OK'
            } catch {
                Write-Output 'PERM:User.Read.All FAIL'
            }
            
            try {
                \$groups = Get-MgGroup -Top 1
                Write-Output 'PERM:Group.Read.All OK'
            } catch {
                Write-Output 'PERM:Group.Read.All FAIL'
            }
            
            Disconnect-MgGraph | Out-Null
        } catch {
            Write-Output \"ERROR:\$_\"
        }
    " 2>&1)
    
    if [[ "$auth_test" == *"SUCCESS:"* ]]; then
        local org_name=$(echo "$auth_test" | grep -o 'SUCCESS:.*' | cut -d: -f2-)
        print_success "Authentication successful: $org_name"
        
        # Check permissions
        echo "$auth_test" | grep "PERM:" | while read -r line; do
            if [[ "$line" == *"OK"* ]]; then
                print_success "  ${line#PERM:}"
            else
                print_warning "  ${line#PERM:}"
            fi
        done
        
        return 0
    else
        print_error "Authentication failed"
        if [[ "$auth_test" == *"ERROR:"* ]]; then
            local error=$(echo "$auth_test" | grep -o 'ERROR:.*' | cut -d: -f2-)
            echo "  Error: $error"
        fi
        return 1
    fi
}

# Function to check admin consent
check_admin_consent() {
    local tenant_id=$1
    local client_id=$2
    
    print_header "Checking Admin Consent"
    
    print_info "Checking if admin consent has been granted..."
    
    local consent_url=$(get_admin_consent_url "$tenant_id" "$client_id")
    print_info "Admin consent URL: $consent_url"
    
    # Note: Actually checking consent status requires additional API calls
    # For now, we'll provide the URL for manual verification
    echo
    print_info "If authentication is failing, admin consent may be required."
    print_info "Have a Global Administrator visit the URL above to grant consent."
    
    return 0
}

# Function to generate diagnostic report
generate_report() {
    print_header "Diagnostic Report"
    
    echo "System Information:"
    echo "  OS: $(uname -s)"
    echo "  PowerShell: ${DIAGNOSTICS[powershell]:-Not checked}"
    echo "  Graph Module: ${DIAGNOSTICS[graph_module]:-Not checked}"
    echo "  Exchange Module: ${DIAGNOSTICS[exo_module]:-Not checked}"
    echo
    
    if [[ -n "${DIAGNOSTICS[tenant_id]}" ]]; then
        echo "Tenant Information:"
        echo "  Tenant ID: ${DIAGNOSTICS[tenant_id]}"
        echo "  Connectivity: ${DIAGNOSTICS[tenant_connectivity]:-OK}"
        echo
    fi
    
    if [[ -n "${DIAGNOSTICS[app_status]}" ]]; then
        echo "App Registration:"
        echo "  Status: ${DIAGNOSTICS[app_status]}"
        echo "  Permissions: ${DIAGNOSTICS[app_permissions]:-Not checked}"
        echo
    fi
    
    if [[ -n "${DIAGNOSTICS[auth_status]}" ]]; then
        echo "Authentication:"
        echo "  Status: ${DIAGNOSTICS[auth_status]}"
        echo
    fi
}

# Function to run automatic fixes
run_automatic_fixes() {
    print_header "Automatic Fixes"
    
    local fixes_applied=0
    
    # Fix: Install PowerShell modules
    if [[ "${DIAGNOSTICS[graph_module]}" == "Not installed" ]]; then
        read -p "Install Microsoft Graph PowerShell module? (y/n): " INSTALL_GRAPH
        if [[ "$INSTALL_GRAPH" =~ ^[Yy]$ ]]; then
            print_info "Installing Microsoft Graph module..."
            $POWERSHELL_CMD -Command "Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber"
            if [[ $? -eq 0 ]]; then
                print_success "Microsoft Graph module installed"
                fixes_applied=$((fixes_applied + 1))
            else
                print_error "Failed to install Microsoft Graph module"
            fi
        fi
    fi
    
    if [[ $fixes_applied -gt 0 ]]; then
        print_success "Applied $fixes_applied fix(es)"
    else
        print_info "No automatic fixes needed or applied"
    fi
}

# Main troubleshooting flow
main() {
    # Step 1: Check prerequisites
    check_powershell_installation
    if [[ $? -eq 0 ]]; then
        check_powershell_modules
    fi
    
    # Step 2: Get configuration to test
    print_header "Configuration to Test"
    
    # Look for existing config files
    local config_file=""
    if [[ -f "$SCRIPT_DIR/prowler-m365-config.env" ]]; then
        config_file="$SCRIPT_DIR/prowler-m365-config.env"
        print_info "Found configuration file: $config_file"
        read -p "Use this configuration? (y/n): " USE_CONFIG
        
        if [[ "$USE_CONFIG" =~ ^[Yy]$ ]]; then
            source "$config_file"
            TENANT_ID="${M365_TENANT_ID:-$AZURE_TENANT_ID}"
            CLIENT_ID="${M365_CLIENT_ID:-$AZURE_CLIENT_ID}"
            CLIENT_SECRET="${M365_CLIENT_SECRET:-$AZURE_CLIENT_SECRET}"
        else
            config_file=""
        fi
    fi
    
    if [[ -z "$config_file" ]]; then
        # Manual input
        read -p "Enter tenant domain (e.g., contoso.onmicrosoft.com): " TENANT_DOMAIN
        read -p "Enter Client ID (optional): " CLIENT_ID
        read -sp "Enter Client Secret (optional): " CLIENT_SECRET
        echo
        
        if [[ -n "$TENANT_DOMAIN" ]]; then
            test_tenant_connectivity "$TENANT_DOMAIN"
            TENANT_ID="${DIAGNOSTICS[tenant_id]}"
        else
            read -p "Enter Tenant ID: " TENANT_ID
        fi
    fi
    
    # Step 3: Run diagnostics
    if [[ -n "$TENANT_ID" ]]; then
        if [[ -n "$CLIENT_ID" ]]; then
            check_app_registration "$TENANT_ID" "$CLIENT_ID"
            
            if [[ -n "$CLIENT_SECRET" ]]; then
                test_authentication "$TENANT_ID" "$CLIENT_ID" "$CLIENT_SECRET"
            fi
            
            check_admin_consent "$TENANT_ID" "$CLIENT_ID"
        fi
    fi
    
    # Step 4: Generate report
    generate_report
    
    # Step 5: Offer automatic fixes
    read -p "Would you like to attempt automatic fixes? (y/n): " RUN_FIXES
    if [[ "$RUN_FIXES" =~ ^[Yy]$ ]]; then
        run_automatic_fixes
    fi
    
    # Step 6: Additional help
    print_header "Additional Resources"
    
    echo "If issues persist:"
    echo "1. Ensure you have the required admin roles in M365"
    echo "2. Check if conditional access policies are blocking the app"
    echo "3. Verify the app registration has the correct API permissions"
    echo "4. Ensure admin consent has been granted"
    echo
    echo "For a fresh setup, run: ./all-in-one-setup.sh"
    echo "To remove and start over: ./cleanup-prowler-m365.sh"
}

# Run main troubleshooting
main