# Prowler M365 Authentication Scripts

This directory contains scripts for setting up Microsoft 365 authentication for Prowler security scanning. These scripts mirror the structure and approach of the Azure authentication scripts.

## Overview

The scripts automate the creation and configuration of:
- Azure AD App Registration with required Microsoft Graph permissions
- Service Principal with client credentials
- Exchange Online permissions (optional)
- Security & Compliance Center access (optional)
- Multi-tenant support for MSPs and enterprises

## Script Structure

### Core Scripts

#### `setup-prowler-m365.sh`
Shared functions library containing:
- PowerShell detection and module management
- App registration creation/management
- Permission configuration
- Authentication testing
- Credential management

#### `all-in-one-setup.sh`
Complete setup for single tenant including:
- PowerShell Core installation (if needed)
- PowerShell module installation
- Interactive authentication flow
- Full configuration with error handling

#### `all-in-one-multi-tenant.sh`
Multi-tenant setup supporting:
- Multiple tenant configuration in one session
- Separate credentials per tenant
- Consolidated configuration file
- Batch processing capabilities

#### `single-tenant-setup.sh`
Core logic script with CLI arguments:
```bash
./single-tenant-setup.sh --domain contoso.onmicrosoft.com --email admin@contoso.com
```

### Utility Scripts

#### `cleanup-prowler-m365.sh`
Removes all created resources:
- App registrations
- Service principals
- Exchange Online role groups
- Local credential files

#### `troubleshoot-m365-auth.sh`
Diagnostic tool that:
- Checks prerequisites
- Tests authentication
- Validates permissions
- Provides automatic fixes

### Customer Package

#### `create-customer-package.sh`
Creates a distributable package with:
- All necessary scripts
- Customer-friendly documentation
- Security-focused credential template

## Prerequisites

### Software Requirements
- **PowerShell Core** (6.0+) or **Windows PowerShell** (5.1+)
- **Microsoft Graph PowerShell Module**
- **Exchange Online Management Module** (optional)
- **bash** shell environment

### Permission Requirements

#### Minimum Requirements
- **Application Administrator** role (to create app registration)
- **Global Administrator** for admin consent (can be different user)

#### Full Automation Requirements
- **Global Administrator** role (includes all necessary permissions)
- **Exchange Administrator** role (for Exchange Online setup)
- **Compliance Administrator** role (for Security & Compliance)

## Usage

### Quick Start (Single Tenant)

1. Run the all-in-one script:
   ```bash
   ./all-in-one-setup.sh
   ```

2. Follow the interactive prompts:
   - Enter your M365 tenant domain
   - Sign in with admin credentials
   - Grant admin consent when prompted

3. Save the generated credentials from `prowler-m365-config.env`

### Multi-Tenant Setup

1. Run the multi-tenant script:
   ```bash
   ./all-in-one-multi-tenant.sh
   ```

2. Add each tenant:
   - Enter tenant domain
   - Provide admin email
   - Repeat for each tenant

3. Credentials saved to `tenant-configs/` directory

### Advanced Usage

For scripted/automated deployments:
```bash
./single-tenant-setup.sh \
  --domain contoso.onmicrosoft.com \
  --email admin@contoso.com \
  --output custom-config.env \
  --skip-exchange
```

## Created Permissions

### Microsoft Graph API Permissions (Application)
- `Directory.Read.All` - Read directory data
- `User.Read.All` - Read all users' profiles
- `Group.Read.All` - Read all groups
- `Policy.Read.All` - Read organization policies
- `RoleManagement.Read.All` - Read directory RBAC settings
- `SecurityEvents.Read.All` - Read security events
- `AuditLog.Read.All` - Read audit log data
- `Organization.Read.All` - Read organization information
- `Application.Read.All` - Read all applications
- `Mail.Read` - Read mail in all mailboxes
- `MailboxSettings.Read` - Read mailbox settings
- `Calendars.Read` - Read calendars in all mailboxes
- `Contacts.Read` - Read contacts in all mailboxes
- `Files.Read.All` - Read files in all sites
- `Sites.Read.All` - Read items in all site collections
- `UserAuthenticationMethod.Read.All` - Read users' authentication methods

### Exchange Online Permissions (Optional)
- View-Only Organization Management
- View-Only Recipients
- View-Only Configuration

## Security Considerations

### Credential Storage
- Credentials saved with `600` permissions (owner read/write only)
- Environment variable format for easy integration
- Separate files per tenant in multi-tenant setups

### Best Practices
1. **Never commit credentials** to version control
2. **Use certificate-based auth** for production (future enhancement)
3. **Rotate secrets regularly** (annual expiration by default)
4. **Limit app permissions** to least privilege needed
5. **Monitor app sign-ins** via Azure AD logs

## Troubleshooting

### Common Issues

**PowerShell Module Not Found**
```bash
# The scripts will auto-install, or manually:
pwsh -Command "Install-Module Microsoft.Graph -Scope CurrentUser"
```

**Permission Denied Creating App**
- Verify you have Application Administrator or Global Administrator role
- Check if app registrations are restricted in your tenant

**Admin Consent Required**
- The script provides a URL for manual consent
- Must be completed by Global Administrator

**Authentication Test Fails**
- Wait 1-2 minutes for permissions to propagate
- Run `./troubleshoot-m365-auth.sh` for diagnostics
- Check if conditional access policies block service principals

### Getting Help

1. Run the troubleshooting script:
   ```bash
   ./troubleshoot-m365-auth.sh
   ```

2. Check prerequisites are installed
3. Verify admin roles and permissions
4. Review error messages for specific issues

## Differences from Azure Scripts

### Authentication Method
- Uses PowerShell modules instead of Azure CLI
- Leverages Microsoft Graph PowerShell SDK
- Supports both PowerShell Core and Windows PowerShell

### Additional Services
- Includes Exchange Online configuration
- Optional Security & Compliance Center setup
- More comprehensive Graph API permissions

### Multi-Service Architecture
- Connects to multiple M365 services
- Service-specific error handling
- Enhanced permission validation

## Contributing

When modifying these scripts:
1. Maintain compatibility with both PowerShell versions
2. Follow the existing error handling patterns
3. Update both technical and customer documentation
4. Test with single and multi-tenant scenarios
5. Ensure cleanup scripts remove all created resources

## License

These scripts are part of the Prowler project and follow the same license terms.