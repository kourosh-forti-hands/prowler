# AWS Security Assessment Setup Instructions

Thank you for choosing our security assessment services. This guide will help you deploy the necessary AWS resources to enable secure, read-only access for security scanning of your AWS environment.

## Overview

You will be deploying a CloudFormation template that creates an IAM role with read-only permissions. This role allows our security assessment tool to analyze your AWS environment without making any changes to your resources.

## Prerequisites

Before you begin, ensure you have:

1. AWS account access with permissions to:
   - Create IAM roles
   - Deploy CloudFormation stacks
2. The CloudFormation template file provided by our team
3. The External ID provided by our team (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

## Deployment Instructions

### Step 1: Log into AWS Console

1. Navigate to [https://console.aws.amazon.com](https://console.aws.amazon.com)
2. Sign in with your AWS credentials
3. Ensure you're in the correct AWS account (check account ID in top-right corner)

### Step 2: Deploy the CloudFormation Stack

1. **Navigate to CloudFormation**
   - In the AWS Console, search for "CloudFormation" in the top search bar
   - Click on **CloudFormation** service

2. **Create New Stack**
   - Click the **Create stack** button
   - Select **With new resources (standard)**

3. **Upload Template**
   - In the "Specify template" section, select **Upload a template file**
   - Click **Choose file** and select the CloudFormation template we provided
   - Click **Next**

4. **Configure Stack Details**
   - **Stack name**: Enter `prowler-security-assessment` (or your preferred name)
   - **ExternalId**: Enter the External ID we provided
     - This should be in the format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
     - **Important**: Copy this exactly as provided to ensure proper authentication
   - Click **Next**

5. **Configure Stack Options**
   - Leave all options at their default values
   - Click **Next**

6. **Review and Deploy**
   - Review all settings
   - At the bottom, check the box:
     - ☑️ **I acknowledge that AWS CloudFormation might create IAM resources**
   - Click **Submit**

7. **Monitor Deployment**
   - The stack will show status "CREATE_IN_PROGRESS"
   - Wait 1-2 minutes for status to change to "CREATE_COMPLETE"
   - If the stack fails, check the "Events" tab for error details

### Step 3: Retrieve the Role ARN

1. **Option A: From CloudFormation Outputs**
   - In CloudFormation console, click on your stack name
   - Go to the **Outputs** tab
   - Copy the value for **RoleARN**

2. **Option B: From IAM Console**
   - Navigate to IAM service
   - Click on **Roles** in the left menu
   - Search for "ProwlerScan"
   - Click on the role name
   - Copy the **Role ARN** from the role summary

### Step 4: Provide Information to Our Team

Please send the following information to your security assessment contact:

1. **Role ARN**: `arn:aws:iam::YOUR-ACCOUNT-ID:role/ProwlerScan`
2. **AWS Account ID**: Your 12-digit AWS account ID
3. **Deployment Status**: Confirmation that the stack deployed successfully

## What Gets Deployed

The CloudFormation template creates a single IAM role with:

- **Role Name**: `ProwlerScan`
- **Permissions**: Read-only access to AWS services for security assessment
- **Trust Relationship**: Configured to allow our assessment service to assume the role
- **External ID**: Additional security measure to prevent unauthorized access

### Security Information

- ✅ **Read-Only Access**: The role cannot modify, delete, or create any resources
- ✅ **No Credentials Stored**: We only store the role ARN, not any credentials
- ✅ **Audit Trail**: All actions are logged in AWS CloudTrail
- ✅ **Time-Limited**: You can delete the stack anytime to revoke access

## Troubleshooting

### Common Issues

**Stack Creation Failed**
- Ensure you have permissions to create IAM roles
- Check the CloudFormation "Events" tab for specific errors
- Verify the External ID was entered correctly (case-sensitive)

**Invalid Template Error**
- Ensure you're uploading the correct file we provided
- Don't modify the template file before uploading

**Permission Denied**
- Your AWS user needs IAM and CloudFormation permissions
- Contact your AWS administrator if you lack permissions

### Getting Help

If you encounter any issues:

1. Take a screenshot of any error messages
2. Note the exact step where the issue occurred
3. Contact your security assessment representative

## Post-Deployment

### Verification

After successful deployment:
- The stack status shows "CREATE_COMPLETE"
- A role named "ProwlerScan" exists in IAM
- You have the Role ARN to provide to our team

### Removing Access

To revoke access after the assessment:

1. Go to CloudFormation console
2. Select the stack (e.g., "prowler-security-assessment")
3. Click "Delete"
4. Confirm deletion

This will remove all resources created by the template.

## Frequently Asked Questions

**Q: What can the security assessment tool access?**
A: Only read access to AWS resources and configurations. No ability to modify anything.

**Q: How long will the assessment take?**
A: Initial scans typically complete within 30-60 minutes, depending on account size.

**Q: Can I limit what regions are scanned?**
A: Yes, please inform your security contact of any region restrictions.

**Q: Will this impact my running services?**
A: No, the assessment uses read-only API calls that don't affect service operation.

**Q: Is the External ID sensitive information?**
A: The External ID is not secret but should only be shared with authorized personnel.

---

*Thank you for enabling this security assessment. If you have any questions or concerns, please don't hesitate to contact your security assessment representative.*