#!/usr/bin/env python3
"""
Add SNS notifications to all remediation functions automatically.
This script modifies remediation files to include notification calls.
"""

import re

# Define notification templates for each function type
NOTIFICATION_TEMPLATES = {
    # RDS Remediations
    "enable_rds_encryption": {
        "action": "Enabled RDS encryption",
        "title": "RDS Instance Encryption Enabled",
        "description": "RDS instance {resource_id} was not encrypted - automatically enabled encryption",
        "priority": "CRITICAL",
        "frameworks": ["PCI-DSS-3.4.1", "SOC2-CC6.7", "HIPAA-164.312"]
    },
    "disable_rds_public_access": {
        "action": "Disabled RDS public access",
        "title": "RDS Public Access Disabled",
        "description": "RDS instance {resource_id} was publicly accessible - automatically disabled public access",
        "priority": "CRITICAL",
        "frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.3.2"]
    },
    "enable_rds_multi_az": {
        "action": "Enabled RDS Multi-AZ",
        "title": "RDS Multi-AZ Enabled",
        "description": "RDS instance {resource_id} was not Multi-AZ - automatically enabled Multi-AZ deployment",
        "priority": "HIGH",
        "frameworks": ["SOC2-A1.2"]
    },
    "enable_rds_deletion_protection": {
        "action": "Enabled RDS deletion protection",
        "title": "RDS Deletion Protection Enabled",
        "description": "RDS instance {resource_id} did not have deletion protection - automatically enabled",
        "priority": "MEDIUM",
        "frameworks": ["SOC2-CC7.3"]
    },
    "revoke_rds_snapshot_public_access": {
        "action": "Revoked RDS snapshot public access",
        "title": "RDS Snapshot Public Access Revoked",
        "description": "RDS snapshot {resource_id} was public - automatically revoked public access",
        "priority": "CRITICAL",
        "frameworks": ["PCI-DSS-3.3", "SOC2-CC6.6"]
    },

    # Security Group Remediations
    "revoke_open_ssh_rule": {
        "action": "Revoked SSH access rule",
        "title": "Security Group SSH Access Revoked",
        "description": "Security group {resource_id} had SSH open to 0.0.0.0/0 - automatically revoked",
        "priority": "CRITICAL",
        "frameworks": ["PCI-DSS-1.3.1", "CIS-5.2", "SOC2-CC6.6"]
    },
    "revoke_open_rdp_rule": {
        "action": "Revoked RDP access rule",
        "title": "Security Group RDP Access Revoked",
        "description": "Security group {resource_id} had RDP open to 0.0.0.0/0 - automatically revoked",
        "priority": "CRITICAL",
        "frameworks": ["PCI-DSS-1.3.1", "CIS-5.3"]
    },
    "revoke_open_database_rule": {
        "action": "Revoked database port access",
        "title": "Security Group Database Access Revoked",
        "description": "Security group {resource_id} had database ports open - automatically revoked",
        "priority": "CRITICAL",
        "frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6"]
    },
    "revoke_all_ingress_from_default_sg": {
        "action": "Revoked all ingress from default security group",
        "title": "Default Security Group Rules Revoked",
        "description": "Default security group {resource_id} had ingress rules - automatically revoked all rules",
        "priority": "HIGH",
        "frameworks": ["CIS-5.4", "PCI-DSS-1.3.1"]
    },

    # IAM Remediations (excluding MFA which already has notifications)
    "disable_iam_access_key": {
        "action": "Disabled IAM access key",
        "title": "IAM Access Key Disabled",
        "description": "IAM user {resource_id} had access keys >90 days old - automatically disabled",
        "priority": "HIGH",
        "frameworks": ["PCI-DSS-8.2.4", "CIS-1.14", "SOC2-CC6.1"]
    },
    "delete_iam_user_inline_policy": {
        "action": "Deleted IAM user inline policy",
        "title": "IAM User Inline Policy Deleted",
        "description": "IAM user {resource_id} had inline policy - automatically deleted",
        "priority": "MEDIUM",
        "frameworks": ["CIS-1.16", "SOC2-CC6.3", "NIST-AC-6"]
    },
    "detach_iam_user_policy": {
        "action": "Detached IAM user policy",
        "title": "IAM User Policy Detached",
        "description": "IAM user {resource_id} had policies - automatically detached",
        "priority": "MEDIUM",
        "frameworks": ["CIS-1.16", "SOC2-CC6.3"]
    },
}

def add_notification_to_function(content, function_name, file_path):
    """Add notification call to a specific function."""
    if function_name not in NOTIFICATION_TEMPLATES:
        return content, False

    template = NOTIFICATION_TEMPLATES[function_name]

    # Find the function's return statement
    # Pattern: look for "return remediation_log" within function scope
    lines = content.split('\n')

    # Find function definition
    func_start = -1
    for i, line in enumerate(lines):
        if f'def {function_name}(' in line:
            func_start = i
            break

    if func_start == -1:
        return content, False

    # Find the return statement for this function
    for i in range(func_start + 1, len(lines)):
        line = lines[i]
        if line.strip().startswith('def '):
            break
        if 'return remediation_log' in line:
            # Found the return statement - check if notification already exists
            has_notification = False
            for j in range(max(0, i-20), i):
                if 'send_remediation_notification' in lines[j]:
                    has_notification = True
                    break

            if not has_notification:
                # Build notification call
                frameworks_str = str(template['frameworks'])

                notification_code = f'''
    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="{template['action']}",
            resource_id=resource_id,
            resource_type="{'aws.rds.instance' if 'rds' in function_name else 'aws.iam.user' if 'iam' in function_name else 'aws.ec2.security-group'}",
            finding_title="{template['title']}",
            finding_description="{template['description']}",
            finding_priority="{template['priority']}",
            compliance_frameworks={frameworks_str},
            region=region,
        )
'''
                # Insert before return
                lines.insert(i, notification_code)
                return '\n'.join(lines), True

    return content, False

def process_file(file_path):
    """Process a single remediation file."""
    print(f"Processing {file_path}...")

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    modified = False
    for function_name in NOTIFICATION_TEMPLATES.keys():
        if f'def {function_name}(' in content:
            content, was_modified = add_notification_to_function(content, function_name, file_path)
            if was_modified:
                modified = True
                print(f"  [OK] Added notification to {function_name}")

    if modified:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  [OK] File updated")
    else:
        print(f"  [INFO] No modifications needed")

if __name__ == '__main__':
    files = [
        'remediations/rds_remediations.py',
        'remediations/sg_remediations.py',
        'remediations/iam_remediations.py'
    ]

    for file_path in files:
        process_file(file_path)

    print("\n[OK] All files processed!")
