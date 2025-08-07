#!/bin/bash

# Creates a clean customer package with only necessary files for M365 setup
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_NAME="prowler-m365-setup"
PACKAGE_DIR="$SCRIPT_DIR/$PACKAGE_NAME"

echo "🚀 Creating customer package for M365..."

# Clean and create package directory
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Copy essential scripts
echo "📋 Copying scripts..."
cp "$SCRIPT_DIR/setup-prowler-m365.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/all-in-one-setup.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/all-in-one-multi-tenant.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/single-tenant-setup.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/cleanup-prowler-m365.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/troubleshoot-m365-auth.sh" "$PACKAGE_DIR/"

# Copy customer documentation
cp "$SCRIPT_DIR/CUSTOMER-README.md" "$PACKAGE_DIR/README.md"

# Create credential collection template
cat > "$PACKAGE_DIR/SHARE-THESE-CREDENTIALS.md" << 'EOF'
# M365 Credentials to Share

After running the setup script, please provide these details:

## ✅ Required Credentials (Share via Secure Channel):
- **Tenant ID:** `________________________`
- **Client ID:** `________________________`
- **Client Secret:** `________________________` 🔐 **USE SECURE TRANSMISSION**

## 🔐 Security Instructions:
- Use encrypted email or secure file transfer service
- Do not send credentials in plain text emails
- Do not include in screenshots
- Delete from your system after secure transmission

## Setup Status:
- [ ] Script completed without errors
- [ ] prowler-m365-config.env file was created
- [ ] Admin consent granted successfully
- [ ] Authentication test passed

## Tenant Information:
- **Tenant Domain:** `________________________`
- **Admin Email Used:** `________________________`
- **Exchange Online Configured:** [ ] Yes [ ] No

**Next Steps:** Your administrator will use these credentials to configure Prowler M365 scanning.
EOF

# Create quick start guide
cat > "$PACKAGE_DIR/QUICK-START.md" << 'EOF'
# Quick Start Guide

## For Single Tenant Setup:
```bash
bash all-in-one-setup.sh
```

## For Multiple Tenants Setup:
```bash
bash all-in-one-multi-tenant.sh
```

## Need Help?
```bash
bash troubleshoot-m365-auth.sh
```

## Important Files After Setup:
- `prowler-m365-config.env` - Your credentials (DO NOT SHARE FILE)
- `SHARE-THESE-CREDENTIALS.md` - Template for providing credentials
- `cleanup-prowler-m365.sh` - Remove all created resources

## Prerequisites:
- Global Administrator or Application Administrator role
- PowerShell (will be installed automatically if missing)
- Internet connection

**⚠️ Security Warning:** Never share your Client Secret or prowler-m365-config.env file contents in plain text!
EOF

# Create PowerShell installation guide
cat > "$PACKAGE_DIR/POWERSHELL-INSTALL.md" << 'EOF'
# PowerShell Installation Guide

The setup scripts require PowerShell. They will attempt automatic installation, but you can install manually if needed.

## Windows
- **Windows 10/11:** PowerShell 5.1 is pre-installed
- **PowerShell Core:** Download from https://aka.ms/powershell

## macOS
```bash
# Using Homebrew
brew install --cask powershell

# Using direct download
# Visit https://aka.ms/powershell and download the .pkg file
```

## Linux

### Ubuntu/Debian
```bash
# Install prerequisites
sudo apt-get update
sudo apt-get install -y wget apt-transport-https software-properties-common

# Download Microsoft repository GPG keys
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb

# Register repository
sudo dpkg -i packages-microsoft-prod.deb

# Install PowerShell
sudo apt-get update
sudo apt-get install -y powershell
```

### RHEL/CentOS
```bash
# Register repository
curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo

# Install PowerShell
sudo yum install -y powershell
```

## Verification
After installation, verify PowerShell is working:
```bash
pwsh --version
```

The setup scripts will automatically install required PowerShell modules.
EOF

# Make scripts executable
chmod +x "$PACKAGE_DIR"/*.sh

# Create package summary
cat > "$PACKAGE_DIR/PACKAGE-CONTENTS.txt" << EOF
Prowler M365 Setup Package
Generated: $(date)

🎯 Start Here: README.md

📁 Main Scripts:
  all-in-one-setup.sh             → Complete single tenant setup
  all-in-one-multi-tenant.sh      → Multiple tenants setup
  troubleshoot-m365-auth.sh       → Diagnostic and troubleshooting
  cleanup-prowler-m365.sh         → Remove all created resources

📄 Documentation:
  README.md                       → Complete setup instructions
  QUICK-START.md                  → Quick reference guide
  SHARE-THESE-CREDENTIALS.md      → Template for sharing credentials
  POWERSHELL-INSTALL.md           → PowerShell installation guide
  
🔧 Support Files:
  setup-prowler-m365.sh           → Shared functions library
  single-tenant-setup.sh          → Core single tenant logic

💡 After Setup:
  - Follow SHARE-THESE-CREDENTIALS.md to provide credentials back
  - Keep prowler-m365-config.env file secure and local
  - Run troubleshoot-m365-auth.sh if you encounter issues
EOF

echo "✅ Customer package created: $PACKAGE_DIR"
echo ""
echo "📦 Package contents:"
ls -la "$PACKAGE_DIR"
echo ""
echo "🎁 To create ZIP for distribution:"
echo "   cd '$SCRIPT_DIR' && zip -r $PACKAGE_NAME.zip $PACKAGE_NAME/"
echo ""
echo "📧 Customer instructions:"
echo "   1. Send them the ZIP file"
echo "   2. Ask them to run: bash all-in-one-setup.sh (or multi-tenant version)"
echo "   3. Request they fill out SHARE-THESE-CREDENTIALS.md with ALL credentials"
echo "   4. Have them send credentials back via secure channel (encrypted email/file transfer)"
echo ""
echo "⚡ Package Features:"
echo "   • Automatic PowerShell installation"
echo "   • Comprehensive error handling"
echo "   • Multi-tenant support"
echo "   • Built-in troubleshooting"
echo "   • Security-focused credential handling"