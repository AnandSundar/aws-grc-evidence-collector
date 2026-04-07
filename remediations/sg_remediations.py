"""
Security group remediation functions for common compliance violations.

This module provides auto-remediation functions for EC2 security group compliance issues
including open SSH, RDP, database ports, and default security group rules.
"""

import boto3
import logging
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional, List
from datetime import datetime
import ipaddress

# Import notification helper
from .remediation_registry import send_remediation_notification

# Configure logging
logger = logging.getLogger(__name__)


# ANSI color codes for terminal output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def _find_open_port_rule(
    group_id: str, port: int, ec2_client: boto3.client, protocol: str = "tcp"
) -> Optional[Dict[str, Any]]:
    """Helper function to find an open port rule in a security group.

    Args:
        group_id: The security group ID.
        port: The port number to search for.
        ec2_client: The EC2 client.
        protocol: The protocol to search for. Defaults to 'tcp'.

    Returns:
        The rule dict if found, None otherwise.
    """
    try:
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = response["SecurityGroups"][0]

        for rule in security_group.get("IpPermissions", []):
            if rule.get("IpProtocol") == protocol:
                for port_range in rule.get("FromPort", []):
                    if isinstance(port_range, int) and port_range == port:
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                return {"rule": rule, "ip_range": ip_range}
    except ClientError as e:
        logger.error(f"{Colors.RED}Error finding rule: {e}{Colors.RESET}")

    return None


def revoke_open_ssh_rule(
    group_id: str, rule_id: Optional[str] = None, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Revoke an open SSH rule from a security group.

    This function revokes SSH (port 22) access from 0.0.0.0/0 in a security group.
    Only the specific offending rule is revoked, not the entire security group.

    Args:
        group_id: The security group ID.
        rule_id: Optional rule ID. If not provided, the function will find the rule.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing:
            - action_taken: Description of the remediation action
            - before_state: The state before remediation
            - after_state: The state after remediation
            - success: Boolean indicating if remediation succeeded
            - error: Error message if remediation failed
            - timestamp: When the remediation was attempted
            - compliance_frameworks: List of relevant compliance frameworks
            - resource_id: The security group ID
            - rule_revoked: Details of the rule that was revoked

    Safety:
        Only revokes the specific offending rule, never deletes the entire security group.

    Compliance:
        - PCI-DSS 1.3.1: Implement firewall rules to restrict access
        - CIS 5.2: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
        - SOC2 CC6.6: Logical and physical access controls
    """
    remediation_log = {
        "action_taken": "revoke_open_ssh_rule",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-1.3.1", "CIS-5.2", "SOC2-CC6.6"],
        "resource_id": group_id,
        "resource_type": "security_group",
        "rule_revoked": None,
    }

    try:
        # Create EC2 client
        ec2_client = boto3.client("ec2", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current security group rules: {group_id}{Colors.RESET}"
        )
        before_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = before_state["SecurityGroups"][0]

        ingress_rules = security_group.get("IpPermissions", [])
        remediation_log["before_state"] = {
            "GroupId": security_group.get("GroupId"),
            "GroupName": security_group.get("GroupName"),
            "IngressRules": ingress_rules,
            "TotalIngressRules": len(ingress_rules),
        }

        # Find the SSH rule
        ssh_rule = None
        for rule in ingress_rules:
            if rule.get("IpProtocol") == "tcp":
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                if from_port == 22 and to_port == 22:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            ssh_rule = rule
                            break
                    if ssh_rule:
                        break

        if not ssh_rule:
            remediation_log["success"] = True
            remediation_log["after_state"] = remediation_log["before_state"]
            remediation_log["error"] = "No open SSH rule found"
            logger.info(
                f"{Colors.YELLOW}No open SSH rule found in security group: {group_id}{Colors.RESET}"
            )

    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="Revoked SSH access rule",
            resource_id=resource_id,
            resource_type="aws.ec2.security-group",
            finding_title="Security Group SSH Access Revoked",
            finding_description="Security group {resource_id} had SSH open to 0.0.0.0/0 - automatically revoked",
            finding_priority="CRITICAL",
            compliance_frameworks=['PCI-DSS-1.3.1', 'CIS-5.2', 'SOC2-CC6.6'],
            region=region,
        )

            return remediation_log

        # Revoke the SSH rule
        logger.info(
            f"{Colors.YELLOW}Revoking open SSH rule from security group: {group_id}{Colors.RESET}"
        )
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id, IpPermissions=[ssh_rule]
        )

        # Get after state
        after_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        after_security_group = after_state["SecurityGroups"][0]
        after_ingress_rules = after_security_group.get("IpPermissions", [])

        remediation_log["after_state"] = {
            "GroupId": after_security_group.get("GroupId"),
            "GroupName": after_security_group.get("GroupName"),
            "IngressRules": after_ingress_rules,
            "TotalIngressRules": len(after_ingress_rules),
        }
        remediation_log["rule_revoked"] = ssh_rule

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully revoked open SSH rule from security group: {group_id}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to revoke SSH rule from security group {group_id}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error revoking SSH rule from security group {group_id}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def revoke_open_rdp_rule(
    group_id: str, rule_id: Optional[str] = None, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Revoke an open RDP rule from a security group.

    This function revokes RDP (port 3389) access from 0.0.0.0/0 in a security group.
    Only the specific offending rule is revoked, not the entire security group.

    Args:
        group_id: The security group ID.
        rule_id: Optional rule ID. If not provided, the function will find the rule.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Safety:
        Only revokes the specific offending rule, never deletes the entire security group.

    Compliance:
        - PCI-DSS 1.3.1: Implement firewall rules to restrict access
        - CIS 5.3: Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
    """
    remediation_log = {
        "action_taken": "revoke_open_rdp_rule",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-1.3.1", "CIS-5.3"],
        "resource_id": group_id,
        "resource_type": "security_group",
        "rule_revoked": None,
    }

    try:
        # Create EC2 client
        ec2_client = boto3.client("ec2", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current security group rules: {group_id}{Colors.RESET}"
        )
        before_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = before_state["SecurityGroups"][0]

        ingress_rules = security_group.get("IpPermissions", [])
        remediation_log["before_state"] = {
            "GroupId": security_group.get("GroupId"),
            "GroupName": security_group.get("GroupName"),
            "IngressRules": ingress_rules,
            "TotalIngressRules": len(ingress_rules),
        }

        # Find the RDP rule
        rdp_rule = None
        for rule in ingress_rules:
            if rule.get("IpProtocol") == "tcp":
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                if from_port == 3389 and to_port == 3389:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            rdp_rule = rule
                            break
                    if rdp_rule:
                        break

        if not rdp_rule:
            remediation_log["success"] = True
            remediation_log["after_state"] = remediation_log["before_state"]
            remediation_log["error"] = "No open RDP rule found"
            logger.info(
                f"{Colors.YELLOW}No open RDP rule found in security group: {group_id}{Colors.RESET}"
            )

    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="Revoked RDP access rule",
            resource_id=resource_id,
            resource_type="aws.ec2.security-group",
            finding_title="Security Group RDP Access Revoked",
            finding_description="Security group {resource_id} had RDP open to 0.0.0.0/0 - automatically revoked",
            finding_priority="CRITICAL",
            compliance_frameworks=['PCI-DSS-1.3.1', 'CIS-5.3'],
            region=region,
        )

            return remediation_log

        # Revoke the RDP rule
        logger.info(
            f"{Colors.YELLOW}Revoking open RDP rule from security group: {group_id}{Colors.RESET}"
        )
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id, IpPermissions=[rdp_rule]
        )

        # Get after state
        after_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        after_security_group = after_state["SecurityGroups"][0]
        after_ingress_rules = after_security_group.get("IpPermissions", [])

        remediation_log["after_state"] = {
            "GroupId": after_security_group.get("GroupId"),
            "GroupName": after_security_group.get("GroupName"),
            "IngressRules": after_ingress_rules,
            "TotalIngressRules": len(after_ingress_rules),
        }
        remediation_log["rule_revoked"] = rdp_rule

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully revoked open RDP rule from security group: {group_id}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to revoke RDP rule from security group {group_id}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error revoking RDP rule from security group {group_id}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def revoke_open_database_rule(
    group_id: str, port: int, rule_id: Optional[str] = None, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Revoke an open database rule from a security group.

    This function revokes database port access from 0.0.0.0/0 in a security group.
    Supported ports: 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 27017 (MongoDB), 6379 (Redis).
    Only the specific offending rule is revoked, not the entire security group.

    Args:
        group_id: The security group ID.
        port: The database port number to revoke.
        rule_id: Optional rule ID. If not provided, the function will find the rule.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Safety:
        Only revokes the specific offending rule, never deletes the entire security group.

    Compliance:
        - PCI-DSS 1.3.2: Restrict inbound and outbound traffic
        - SOC2 CC6.6: Logical and physical access controls
    """
    # Supported database ports
    DATABASE_PORTS = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
    }

    remediation_log = {
        "action_taken": "revoke_open_database_rule",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6"],
        "resource_id": group_id,
        "resource_type": "security_group",
        "rule_revoked": None,
        "port": port,
        "database_type": DATABASE_PORTS.get(port, "Unknown"),
    }

    try:
        # Validate port
        if port not in DATABASE_PORTS:
            remediation_log["error"] = (
                f"Unsupported database port: {port}. Supported ports: {list(DATABASE_PORTS.keys())}"
            )
            logger.error(
                f"{Colors.RED}✗ Unsupported database port: {port}{Colors.RESET}"
            )

    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="Revoked database port access",
            resource_id=resource_id,
            resource_type="aws.ec2.security-group",
            finding_title="Security Group Database Access Revoked",
            finding_description="Security group {resource_id} had database ports open - automatically revoked",
            finding_priority="CRITICAL",
            compliance_frameworks=['PCI-DSS-1.3.2', 'SOC2-CC6.6'],
            region=region,
        )

            return remediation_log

        # Create EC2 client
        ec2_client = boto3.client("ec2", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current security group rules: {group_id}{Colors.RESET}"
        )
        before_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = before_state["SecurityGroups"][0]

        ingress_rules = security_group.get("IpPermissions", [])
        remediation_log["before_state"] = {
            "GroupId": security_group.get("GroupId"),
            "GroupName": security_group.get("GroupName"),
            "IngressRules": ingress_rules,
            "TotalIngressRules": len(ingress_rules),
        }

        # Find the database rule
        db_rule = None
        for rule in ingress_rules:
            if rule.get("IpProtocol") == "tcp":
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                if from_port == port and to_port == port:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            db_rule = rule
                            break
                    if db_rule:
                        break

        if not db_rule:
            remediation_log["success"] = True
            remediation_log["after_state"] = remediation_log["before_state"]
            remediation_log["error"] = (
                f"No open {DATABASE_PORTS[port]} rule found on port {port}"
            )
            logger.info(
                f"{Colors.YELLOW}No open {DATABASE_PORTS[port]} rule found in security group: {group_id}{Colors.RESET}"
            )
            return remediation_log

        # Revoke the database rule
        logger.info(
            f"{Colors.YELLOW}Revoking open {DATABASE_PORTS[port]} rule from security group: {group_id}{Colors.RESET}"
        )
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id, IpPermissions=[db_rule]
        )

        # Get after state
        after_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        after_security_group = after_state["SecurityGroups"][0]
        after_ingress_rules = after_security_group.get("IpPermissions", [])

        remediation_log["after_state"] = {
            "GroupId": after_security_group.get("GroupId"),
            "GroupName": after_security_group.get("GroupName"),
            "IngressRules": after_ingress_rules,
            "TotalIngressRules": len(after_ingress_rules),
        }
        remediation_log["rule_revoked"] = db_rule

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully revoked open {DATABASE_PORTS[port]} rule from security group: {group_id}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to revoke database rule from security group {group_id}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error revoking database rule from security group {group_id}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def revoke_all_ingress_from_default_sg(
    group_id: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Revoke all ingress rules from a default security group.

    This function revokes all ingress rules from a default security group.
    Default security groups should not have any ingress rules.
    Only rules are revoked, never the security group itself.

    Args:
        group_id: The security group ID (should be a default security group).
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing:
            - action_taken: Description of the remediation action
            - before_state: The state before remediation
            - after_state: The state after remediation
            - success: Boolean indicating if remediation succeeded
            - error: Error message if remediation failed
            - timestamp: When the remediation was attempted
            - compliance_frameworks: List of relevant compliance frameworks
            - resource_id: The security group ID
            - rules_revoked_count: Number of rules revoked

    Safety:
        Only revokes rules, never deletes the security group.

    Compliance:
        - CIS 5.4: Ensure the default security group restricts all traffic
        - PCI-DSS 1.3.1: Implement firewall rules to restrict access
    """
    remediation_log = {
        "action_taken": "revoke_all_ingress_from_default_sg",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["CIS-5.4", "PCI-DSS-1.3.1"],
        "resource_id": group_id,
        "resource_type": "security_group",
        "rules_revoked_count": 0,
    }

    try:
        # Create EC2 client
        ec2_client = boto3.client("ec2", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current security group rules: {group_id}{Colors.RESET}"
        )
        before_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = before_state["SecurityGroups"][0]

        # Check if this is a default security group
        group_name = security_group.get("GroupName", "")
        is_default = group_name == "default" or "default" in group_name.lower()

        ingress_rules = security_group.get("IpPermissions", [])
        remediation_log["before_state"] = {
            "GroupId": security_group.get("GroupId"),
            "GroupName": group_name,
            "IsDefault": is_default,
            "IngressRules": ingress_rules,
            "TotalIngressRules": len(ingress_rules),
        }

        if not ingress_rules:
            remediation_log["success"] = True
            remediation_log["after_state"] = remediation_log["before_state"]
            logger.info(
                f"{Colors.YELLOW}No ingress rules found in security group: {group_id}{Colors.RESET}"
            )

    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="Revoked all ingress from default security group",
            resource_id=resource_id,
            resource_type="aws.ec2.security-group",
            finding_title="Default Security Group Rules Revoked",
            finding_description="Default security group {resource_id} had ingress rules - automatically revoked all rules",
            finding_priority="HIGH",
            compliance_frameworks=['CIS-5.4', 'PCI-DSS-1.3.1'],
            region=region,
        )

            return remediation_log

        # Revoke all ingress rules
        logger.info(
            f"{Colors.YELLOW}Revoking all ingress rules from security group: {group_id}{Colors.RESET}"
        )
        rules_revoked = 0
        for rule in ingress_rules:
            try:
                ec2_client.revoke_security_group_ingress(
                    GroupId=group_id, IpPermissions=[rule]
                )
                rules_revoked += 1
            except ClientError as e:
                logger.warning(
                    f"{Colors.YELLOW}Warning: Failed to revoke rule: {e}{Colors.RESET}"
                )

        # Get after state
        after_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        after_security_group = after_state["SecurityGroups"][0]
        after_ingress_rules = after_security_group.get("IpPermissions", [])

        remediation_log["after_state"] = {
            "GroupId": after_security_group.get("GroupId"),
            "GroupName": after_security_group.get("GroupName"),
            "IsDefault": is_default,
            "IngressRules": after_ingress_rules,
            "TotalIngressRules": len(after_ingress_rules),
        }
        remediation_log["rules_revoked_count"] = rules_revoked

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully revoked {rules_revoked} ingress rule(s) from security group: {group_id}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to revoke ingress rules from security group {group_id}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error revoking ingress rules from security group {group_id}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def add_sg_description(
    group_id: str, description: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Add a description tag to a security group.

    This function adds a Description tag to a security group for better
    governance and documentation purposes.

    Args:
        group_id: The security group ID.
        description: The description text to add as a tag.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Compliance:
        - General governance: Proper documentation of security resources
    """
    remediation_log = {
        "action_taken": "add_sg_description",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["GOVERNANCE"],
        "resource_id": group_id,
        "resource_type": "security_group",
    }

    try:
        # Create EC2 client
        ec2_client = boto3.client("ec2", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current security group details: {group_id}{Colors.RESET}"
        )
        before_state = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = before_state["SecurityGroups"][0]

        # Get existing tags
        tags_response = ec2_client.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [group_id]},
                {"Name": "key", "Values": ["Description"]},
            ]
        )

        existing_description = None
        for tag in tags_response.get("Tags", []):
            if tag.get("Key") == "Description":
                existing_description = tag.get("Value")
                break

        remediation_log["before_state"] = {
            "GroupId": security_group.get("GroupId"),
            "GroupName": security_group.get("GroupName"),
            "DescriptionTag": existing_description,
            "AllTags": security_group.get("Tags", []),
        }

        # Add or update the Description tag
        logger.info(
            f"{Colors.YELLOW}Adding Description tag to security group: {group_id}{Colors.RESET}"
        )
        ec2_client.create_tags(
            Resources=[group_id], Tags=[{"Key": "Description", "Value": description}]
        )

        # Get after state
        after_tags_response = ec2_client.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [group_id]},
                {"Name": "key", "Values": ["Description"]},
            ]
        )

        after_description = None
        for tag in after_tags_response.get("Tags", []):
            if tag.get("Key") == "Description":
                after_description = tag.get("Value")
                break

        remediation_log["after_state"] = {
            "GroupId": security_group.get("GroupId"),
            "GroupName": security_group.get("GroupName"),
            "DescriptionTag": after_description,
        }

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully added Description tag to security group: {group_id}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to add Description tag to security group {group_id}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error adding Description tag to security group {group_id}: {str(e)}{Colors.RESET}"
        )

    return remediation_log
