# Prowler M365 Setup - Customer Guide

## What You'll Be Running

This package contains secure scripts to set up Microsoft 365 authentication for Prowler security scanning. The scripts will create the necessary Azure AD app registration and permissions.

## Prerequisites

### Required Permissions
You need **ONE** of these permission combinations:
- **Global Administrator** role (easiest option)
- **Application Administrator** + manual admin consent from Global Admin

### Required Software
- PowerShell Core or Windows PowerShell
- Internet connection
- Microsoft 365 tenant access

## Quick Setup

### Option 1: Single Tenant
```bash
bash all-in-one-setup.sh
```

### Option 2: Multiple Tenants  
```bash
bash all-in-one-multi-tenant.sh
```

## What Happens During Setup

1. **Prerequisites Check** - Installs PowerShell and required modules
2. **Microsoft 365 Login** - You'll authenticate to your M365 tenant
3. **App Registration** - Creates "Prowler Security Scanner" app in Azure AD
4. **Permissions Setup** - Configures read-only security permissions
5. **Credential Generation** - Creates secure authentication credentials

## Expected Output

After successful setup, you'll receive:
- **Tenant ID**: Your M365 tenant identifier
- **Client ID**: Application (app registration) ID
- **Client Secret**: 🔐 **SECURE TRANSMISSION REQUIRED**
- Configuration file: `prowler-m365-config.env`

## What to Share Back

### ✅ Required Credentials to Share:
- **Tenant ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Client ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Client Secret**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` 🔐 **USE SECURE CHANNEL**

### ⚠️ Security Instructions:
- Use encrypted email or secure file transfer service
- Do not send credentials in plain text emails
- Do not include in screenshots
- Delete credentials from your system after secure transmission

## Troubleshooting

If you encounter issues:
```bash
bash troubleshoot-m365-auth.sh
```

### Common Solutions:

**"Connect-MgGraph : The term 'Connect-MgGraph' is not recognized"**
- PowerShell modules need to be installed
- The script will install them automatically

**"Insufficient privileges"**
- You need Application Administrator or Global Administrator role
- Contact your M365 administrator for required permissions

**"Admin consent required"**  
- A URL will be provided for manual consent
- Your Global Administrator must approve the permissions

## Security Information

### What Access Does This Create?
- **Read-only access** to security configurations
- **Cannot modify** any M365 resources
- **Cannot access** user emails or personal data

### Specific Permissions:
- Read organization and user directory information
- Read security events and audit logs
- List policies and authentication methods
- Read Exchange configuration (optional)

## Cleanup (Optional)

To remove all created resources:
```bash
bash cleanup-prowler-m365.sh
```

This removes:
- App registration in Azure AD
- Service principal
- All credentials
- Local configuration files

## Runtime Expectations

- Single tenant: 5-10 minutes
- Multiple tenants: 10-15 minutes per tenant
- Additional time if manual admin consent is required

## Support

1. First run: `bash troubleshoot-m365-auth.sh`
2. Check PowerShell module installation
3. Verify you have required admin roles
4. For permission issues, contact your M365 administrator

**Important:** When requesting support, only share Tenant ID and Client ID. Never share the Client Secret.

---

**🔒 Remember: Keep your Client Secret secure and use secure transmission methods when sharing credentials.**