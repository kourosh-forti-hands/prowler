#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}     Prowler Multi-Cloud Compliance Scanner      ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Function to check if credentials are configured
check_aws_credentials() {
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
        echo -e "${GREEN}✓ AWS credentials detected${NC}"
        return 0
    fi
    return 1
}

check_azure_credentials() {
    if [ -n "$AZURE_CLIENT_ID" ] && [ -n "$AZURE_TENANT_ID" ] && [ -n "$AZURE_CLIENT_SECRET" ]; then
        echo -e "${GREEN}✓ Azure Service Principal credentials detected${NC}"
        return 0
    fi
    return 1
}

check_gcp_credentials() {
    if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ] || [ -n "$CLOUDSDK_AUTH_ACCESS_TOKEN" ]; then
        echo -e "${GREEN}✓ GCP credentials detected${NC}"
        return 0
    fi
    return 1
}

# Function to run Prowler scan for a specific provider
run_prowler_scan() {
    local provider=$1
    local compliance_frameworks=$2
    local additional_args=$3
    
    echo -e "\n${YELLOW}Starting $provider scan...${NC}"
    
    if [ "$SCAN_ALL_COMPLIANCE" == "true" ]; then
        # Get all available compliance frameworks for the provider
        echo -e "${BLUE}Fetching available compliance frameworks for $provider...${NC}"
        frameworks=$(poetry run prowler $provider --list-compliance 2>/dev/null | grep -E '^\s*-' | sed 's/^[[:space:]]*- //' || true)
        
        if [ -z "$frameworks" ]; then
            echo -e "${YELLOW}No compliance frameworks found, running default scan...${NC}"
            poetry run prowler $provider $additional_args \
                --output-formats csv json html \
                --output-directory /home/prowler/output \
                --verbose || true
        else
            # Run scan for each compliance framework
            while IFS= read -r framework; do
                if [ -n "$framework" ]; then
                    echo -e "${BLUE}Scanning $provider for compliance: $framework${NC}"
                    poetry run prowler $provider \
                        --compliance "$framework" \
                        $additional_args \
                        --output-formats csv json html \
                        --output-directory /home/prowler/output \
                        --verbose || true
                fi
            done <<< "$frameworks"
        fi
    else
        # Run with specific compliance frameworks from config
        if [ -n "$compliance_frameworks" ]; then
            for framework in $compliance_frameworks; do
                echo -e "${BLUE}Scanning $provider for compliance: $framework${NC}"
                poetry run prowler $provider \
                    --compliance "$framework" \
                    $additional_args \
                    --output-formats csv json html \
                    --output-directory /home/prowler/output \
                    --verbose || true
            done
        else
            # Run default scan without specific compliance
            echo -e "${BLUE}Running default $provider scan...${NC}"
            poetry run prowler $provider $additional_args \
                --output-formats csv json html \
                --output-directory /home/prowler/output \
                --verbose || true
        fi
    fi
    
    echo -e "${GREEN}✓ $provider scan completed${NC}"
}

# Function to run dashboard
run_dashboard() {
    echo -e "\n${YELLOW}Starting Prowler Dashboard...${NC}"
    echo -e "${BLUE}Dashboard will be available at: http://localhost:${DASHBOARD_PORT}${NC}"
    echo -e "${YELLOW}Note: Dashboard server is not authenticated. Use with caution.${NC}\n"
    
    # Set the HOST environment variable for the dashboard
    export HOST=${DASHBOARD_HOST}
    
    # Run the dashboard
    poetry run prowler dashboard
}

# Main execution
main() {
    local providers_found=false
    local scan_completed=false
    
    echo -e "\n${BLUE}Checking cloud provider credentials...${NC}"
    
    # AWS Scan
    if check_aws_credentials; then
        providers_found=true
        if [ "$AUTO_SCAN" == "true" ] || [ "$1" == "scan" ] || [ "$1" == "scan-and-dashboard" ]; then
            # Configure AWS credentials
            aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
            aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
            [ -n "$AWS_SESSION_TOKEN" ] && aws configure set aws_session_token "$AWS_SESSION_TOKEN"
            [ -n "$AWS_REGION" ] && aws configure set region "$AWS_REGION"
            
            run_prowler_scan "aws" "$AWS_COMPLIANCE_FRAMEWORKS" ""
            scan_completed=true
        fi
    else
        echo -e "${YELLOW}⚠ AWS credentials not configured${NC}"
    fi
    
    # Azure Scan
    if check_azure_credentials; then
        providers_found=true
        if [ "$AUTO_SCAN" == "true" ] || [ "$1" == "scan" ] || [ "$1" == "scan-and-dashboard" ]; then
            local azure_args="--sp-env-auth"
            [ -n "$AZURE_SUBSCRIPTION_ID" ] && azure_args="$azure_args --subscription-ids $AZURE_SUBSCRIPTION_ID"
            
            run_prowler_scan "azure" "$AZURE_COMPLIANCE_FRAMEWORKS" "$azure_args"
            scan_completed=true
        fi
    else
        echo -e "${YELLOW}⚠ Azure credentials not configured${NC}"
    fi
    
    # GCP Scan
    if check_gcp_credentials; then
        providers_found=true
        if [ "$AUTO_SCAN" == "true" ] || [ "$1" == "scan" ] || [ "$1" == "scan-and-dashboard" ]; then
            local gcp_args=""
            [ -n "$GOOGLE_CLOUD_PROJECT" ] && gcp_args="--project-ids $GOOGLE_CLOUD_PROJECT"
            
            # Set up GCP authentication
            if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ] && [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
                gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null || true
            fi
            
            run_prowler_scan "gcp" "$GCP_COMPLIANCE_FRAMEWORKS" "$gcp_args"
            scan_completed=true
        fi
    else
        echo -e "${YELLOW}⚠ GCP credentials not configured${NC}"
    fi
    
    # Check if any providers were found
    if [ "$providers_found" == "false" ]; then
        echo -e "\n${RED}ERROR: No cloud provider credentials configured!${NC}"
        echo -e "${YELLOW}Please configure at least one of the following:${NC}"
        echo -e "  - AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
        echo -e "  - Azure: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET"
        echo -e "  - GCP: GOOGLE_APPLICATION_CREDENTIALS or CLOUDSDK_AUTH_ACCESS_TOKEN"
        exit 1
    fi
    
    # Generate summary if scans were completed
    if [ "$scan_completed" == "true" ]; then
        echo -e "\n${GREEN}==================================================${NC}"
        echo -e "${GREEN}           All Scans Completed Successfully       ${NC}"
        echo -e "${GREEN}==================================================${NC}"
        echo -e "${BLUE}Output files saved to: /home/prowler/output${NC}"
        
        # List generated files
        echo -e "\n${YELLOW}Generated files:${NC}"
        find /home/prowler/output -type f -name "*.csv" -o -name "*.json" -o -name "*.html" | head -20
    fi
    
    # Run dashboard if requested
    if [ "$1" == "dashboard" ] || [ "$1" == "scan-and-dashboard" ]; then
        run_dashboard
    elif [ "$1" == "scan" ]; then
        echo -e "\n${BLUE}Scan completed. To view the dashboard, run with 'dashboard' command.${NC}"
    else
        # Default behavior based on AUTO_SCAN
        if [ "$scan_completed" == "true" ]; then
            echo -e "\n${BLUE}To view the dashboard, restart the container with 'dashboard' command.${NC}"
        fi
    fi
}

# Handle different commands
case "$1" in
    scan)
        AUTO_SCAN="true"
        main "$@"
        ;;
    dashboard)
        main "$@"
        ;;
    scan-and-dashboard)
        AUTO_SCAN="true"
        main "$@"
        ;;
    bash|sh)
        exec "$@"
        ;;
    *)
        # Default behavior
        main "$@"
        ;;
esac