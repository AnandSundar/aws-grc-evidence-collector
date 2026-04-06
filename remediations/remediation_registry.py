"""
Remediation registry for GRC Evidence Platform.

This module provides a centralized registry that maps Config rule names and
EventBridge patterns to their corresponding remediation functions. It also
provides helper functions for executing and validating remediations.
"""

import logging
from typing import Dict, Any, Callable, Optional
from datetime import datetime

# Import remediation functions
from . import s3_remediations
from . import iam_remediations
from . import rds_remediations
from . import sg_remediations

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


# Remediation Registry
# Maps Config rule names and EventBridge patterns to remediation functions
REMEDIATION_REGISTRY: Dict[str, Dict[str, Any]] = {
    # S3 Remediations
    "s3-bucket-public-read-prohibited": {
        "function": s3_remediations.block_s3_public_access,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.1.1"],
        "safety_mode": "AUTO",
    },
    "s3-bucket-public-write-prohibited": {
        "function": s3_remediations.block_s3_public_access,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.1.1"],
        "safety_mode": "AUTO",
    },
    "s3-bucket-server-side-encryption-enabled": {
        "function": s3_remediations.enable_s3_encryption,
        "trigger_type": "CONFIG_RULE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-3.4", "SOC2-CC6.7"],
        "safety_mode": "AUTO",
    },
    "s3-bucket-versioning-enabled": {
        "function": s3_remediations.enable_s3_versioning,
        "trigger_type": "CONFIG_RULE",
        "priority": "MEDIUM",
        "compliance_frameworks": ["SOC2-A1.3", "PCI-DSS-12.3.4"],
        "safety_mode": "AUTO",
    },
    "s3-bucket-logging-enabled": {
        "function": s3_remediations.enable_s3_logging,
        "trigger_type": "CONFIG_RULE",
        "priority": "MEDIUM",
        "compliance_frameworks": ["PCI-DSS-10.2", "SOC2-CC6.8"],
        "safety_mode": "AUTO",
    },
    # IAM Remediations
    "iam-access-keys-rotated": {
        "function": iam_remediations.disable_iam_access_key,
        "trigger_type": "CONFIG_RULE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-8.2.4", "CIS-1.14", "SOC2-CC6.1"],
        "safety_mode": "AUTO",
    },
    "iam-user-mfa-enabled": {
        "function": iam_remediations.enforce_mfa_for_user,
        "trigger_type": "CONFIG_RULE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-8.4.2", "CIS-1.10", "SOC2-CC6.1"],
        "safety_mode": "AUTO",
    },
    "iam-user-inline-policies": {
        "function": iam_remediations.delete_iam_user_inline_policy,
        "trigger_type": "CONFIG_RULE",
        "priority": "MEDIUM",
        "compliance_frameworks": ["CIS-1.16", "SOC2-CC6.3", "NIST-AC-6"],
        "safety_mode": "AUTO",
    },
    "iam-user-no-policies-check": {
        "function": iam_remediations.detach_iam_user_policy,
        "trigger_type": "CONFIG_RULE",
        "priority": "MEDIUM",
        "compliance_frameworks": ["CIS-1.16", "SOC2-CC6.3"],
        "safety_mode": "AUTO",
    },
    "iam-user-unused-credentials-check": {
        "function": iam_remediations.delete_iam_access_key,
        "trigger_type": "CONFIG_RULE",
        "priority": "LOW",
        "compliance_frameworks": ["PCI-DSS-8.2.6", "CIS-1.15"],
        "safety_mode": "AUTO",
    },
    # RDS Remediations
    "rds-storage-encrypted": {
        "function": rds_remediations.enable_rds_encryption,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-3.4.1", "SOC2-CC6.7", "HIPAA-164.312"],
        "safety_mode": "APPROVAL_REQUIRED",  # Requires snapshot and restore
    },
    "rds-instance-public-access-check": {
        "function": rds_remediations.disable_rds_public_access,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.3.2"],
        "safety_mode": "AUTO",
    },
    "rds-multi-az-support": {
        "function": rds_remediations.enable_rds_multi_az,
        "trigger_type": "CONFIG_RULE",
        "priority": "HIGH",
        "compliance_frameworks": ["SOC2-A1.2"],
        "safety_mode": "AUTO",
    },
    "rds-instance-deletion-protection-enabled": {
        "function": rds_remediations.enable_rds_deletion_protection,
        "trigger_type": "CONFIG_RULE",
        "priority": "MEDIUM",
        "compliance_frameworks": ["SOC2-CC7.3"],
        "safety_mode": "AUTO",
    },
    "rds-enhanced-monitoring-enabled": {
        "function": rds_remediations.enable_rds_deletion_protection,  # Placeholder
        "trigger_type": "CONFIG_RULE",
        "priority": "LOW",
        "compliance_frameworks": ["SOC2-CC6.8"],
        "safety_mode": "AUTO",
    },
    "rds-snapshot-public-prohibited": {
        "function": rds_remediations.revoke_rds_snapshot_public_access,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-3.3", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    # Security Group Remediations
    "restricted-ssh": {
        "function": sg_remediations.revoke_open_ssh_rule,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.1", "CIS-5.2", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    "restricted-rdp": {
        "function": sg_remediations.revoke_open_rdp_rule,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.1", "CIS-5.3"],
        "safety_mode": "AUTO",
    },
    "restricted-common-ports": {
        "function": sg_remediations.revoke_open_database_rule,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    "default-security-group-closed": {
        "function": sg_remediations.revoke_all_ingress_from_default_sg,
        "trigger_type": "CONFIG_RULE",
        "priority": "HIGH",
        "compliance_frameworks": ["CIS-5.4", "PCI-DSS-1.3.1"],
        "safety_mode": "AUTO",
    },
    # EventBridge Pattern Mappings
    "PutBucketAcl": {
        "function": s3_remediations.remove_s3_public_acl,
        "trigger_type": "EVENT_BRIDGE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    "PutBucketPolicy": {
        "function": s3_remediations.delete_s3_public_policy,
        "trigger_type": "EVENT_BRIDGE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    "AuthorizeSecurityGroupIngress": {
        "function": sg_remediations.revoke_open_ssh_rule,
        "trigger_type": "EVENT_BRIDGE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.1", "CIS-5.2", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    "CreateAccessKey": {
        "function": iam_remediations.disable_iam_access_key,
        "trigger_type": "EVENT_BRIDGE",
        "priority": "MEDIUM",
        "compliance_frameworks": ["PCI-DSS-8.2.4", "CIS-1.14"],
        "safety_mode": "AUTO",
    },
    "ModifyDBInstance": {
        "function": rds_remediations.disable_rds_public_access,
        "trigger_type": "EVENT_BRIDGE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
}


def get_remediation_function(trigger: str) -> Optional[Callable]:
    """Get the remediation function for a given trigger.

    This function looks up a trigger in the REMEDIATION_REGISTRY and returns
    the corresponding remediation function. If the trigger is not found,
    it returns None.

    Args:
        trigger: The trigger name (Config rule name or EventBridge pattern).

    Returns:
        The remediation function if found, None otherwise.

    Example:
        >>> func = get_remediation_function("s3-bucket-public-read-prohibited")
        >>> if func:
        ...     result = func(bucket_name="my-bucket", region="us-east-1")
    """
    registry_entry = REMEDIATION_REGISTRY.get(trigger)

    if not registry_entry:
        logger.warning(
            f"{Colors.YELLOW}No remediation function found for trigger: {trigger}{Colors.RESET}"
        )
        return None

    remediation_function = registry_entry.get("function")

    if not remediation_function:
        logger.error(
            f"{Colors.RED}Remediation function is None for trigger: {trigger}{Colors.RESET}"
        )
        return None

    logger.info(
        f"{Colors.CYAN}Found remediation function for trigger: {trigger}{Colors.RESET}"
    )
    return remediation_function


def execute_remediation(
    trigger: str,
    resource_id: str,
    region: str = "us-east-1",
    dry_run: bool = False,
    **kwargs,
) -> Dict[str, Any]:
    """Execute a remediation for a given trigger and resource.

    This function retrieves the remediation function from the registry and
    executes it. If dry_run is True, it logs what would happen without
    actually executing the remediation.

    Args:
        trigger: The trigger name (Config rule name or EventBridge pattern).
        resource_id: The ID of the resource to remediate.
        region: The AWS region. Defaults to "us-east-1".
        dry_run: If True, log what would happen without executing. Defaults to False.
        **kwargs: Additional keyword arguments to pass to the remediation function.

    Returns:
        A remediation_log dict containing the remediation details.

    Example:
        >>> result = execute_remediation(
        ...     trigger="s3-bucket-public-read-prohibited",
        ...     resource_id="my-bucket",
        ...     region="us-east-1"
        ... )
    """
    execution_log = {
        "trigger": trigger,
        "resource_id": resource_id,
        "region": region,
        "dry_run": dry_run,
        "timestamp": datetime.utcnow().isoformat(),
        "success": False,
        "error": None,
    }

    # Get the remediation function
    remediation_function = get_remediation_function(trigger)

    if not remediation_function:
        execution_log["error"] = f"No remediation function found for trigger: {trigger}"
        logger.error(f"{Colors.RED}✗ {execution_log['error']}{Colors.RESET}")
        return execution_log

    # Get registry entry for additional context
    registry_entry = REMEDIATION_REGISTRY.get(trigger, {})
    priority = registry_entry.get("priority", "UNKNOWN")
    safety_mode = registry_entry.get("safety_mode", "UNKNOWN")

    logger.info(f"{Colors.CYAN}Executing remediation:{Colors.RESET}")
    logger.info(f"  Trigger: {trigger}")
    logger.info(f"  Resource: {resource_id}")
    logger.info(f"  Region: {region}")
    logger.info(f"  Priority: {priority}")
    logger.info(f"  Safety Mode: {safety_mode}")
    logger.info(f"  Dry Run: {dry_run}")

    # If dry run, log what would happen and return
    if dry_run:
        execution_log["action_taken"] = "DRY_RUN"
        execution_log["success"] = True
        execution_log["message"] = (
            f"Would execute remediation for trigger: {trigger} on resource: {resource_id}"
        )
        logger.info(
            f"{Colors.YELLOW}[DRY RUN] Would execute remediation for trigger: {trigger} on resource: {resource_id}{Colors.RESET}"
        )
        return execution_log

    # Execute the remediation
    try:
        logger.info(f"{Colors.YELLOW}Executing remediation function...{Colors.RESET}")
        remediation_log = remediation_function(resource_id, region=region, **kwargs)

        # Merge execution log with remediation log
        execution_log.update(remediation_log)
        execution_log["success"] = remediation_log.get("success", False)

        if execution_log["success"]:
            logger.info(
                f"{Colors.GREEN}✓ Remediation executed successfully for trigger: {trigger}{Colors.RESET}"
            )
        else:
            logger.error(
                f"{Colors.RED}✗ Remediation failed for trigger: {trigger}{Colors.RESET}"
            )

    except Exception as e:
        execution_log["error"] = str(e)
        execution_log["success"] = False
        logger.error(
            f"{Colors.RED}✗ Error executing remediation for trigger {trigger}: {str(e)}{Colors.RESET}"
        )

    return execution_log


def validate_safety_mode(trigger: str, remediation_mode: str) -> bool:
    """Validate if the remediation mode is compatible with the safety mode.

    This function checks if the specified remediation_mode is compatible with
    the safety_mode defined in the registry for the given trigger.

    Args:
        trigger: The trigger name (Config rule name or EventBridge pattern).
        remediation_mode: The remediation mode to validate (e.g., "AUTO", "APPROVAL_REQUIRED").

    Returns:
        True if the remediation_mode is compatible with safety_mode, False otherwise.

    Example:
        >>> is_valid = validate_safety_mode(
        ...     trigger="rds-storage-encrypted",
        ...     remediation_mode="APPROVAL_REQUIRED"
        ... )
        >>> print(is_valid)
        True
    """
    registry_entry = REMEDIATION_REGISTRY.get(trigger)

    if not registry_entry:
        logger.warning(
            f"{Colors.YELLOW}No registry entry found for trigger: {trigger}{Colors.RESET}"
        )
        return False

    safety_mode = registry_entry.get("safety_mode", "AUTO")

    logger.info(f"{Colors.CYAN}Validating safety mode:{Colors.RESET}")
    logger.info(f"  Trigger: {trigger}")
    logger.info(f"  Safety Mode: {safety_mode}")
    logger.info(f"  Remediation Mode: {remediation_mode}")

    # Safety mode compatibility matrix
    compatibility_matrix = {
        "AUTO": ["AUTO", "MANUAL", "APPROVAL_REQUIRED"],
        "APPROVAL_REQUIRED": ["APPROVAL_REQUIRED"],
        "MANUAL": ["MANUAL", "APPROVAL_REQUIRED"],
    }

    allowed_modes = compatibility_matrix.get(safety_mode, [])

    if remediation_mode in allowed_modes:
        logger.info(
            f"{Colors.GREEN}✓ Remediation mode '{remediation_mode}' is compatible with safety mode '{safety_mode}'{Colors.RESET}"
        )
        return True
    else:
        logger.error(
            f"{Colors.RED}✗ Remediation mode '{remediation_mode}' is NOT compatible with safety mode '{safety_mode}'{Colors.RESET}"
        )
        logger.error(
            f"{Colors.RED}  Allowed modes for '{safety_mode}': {allowed_modes}{Colors.RESET}"
        )
        return False


def list_all_triggers(trigger_type: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """List all triggers in the remediation registry.

    This function returns all triggers in the registry, optionally filtered
    by trigger type (CONFIG_RULE or EVENT_BRIDGE).

    Args:
        trigger_type: Optional filter for trigger type. If None, returns all triggers.

    Returns:
        A dictionary of triggers and their registry entries.

    Example:
        >>> all_triggers = list_all_triggers()
        >>> config_triggers = list_all_triggers(trigger_type="CONFIG_RULE")
    """
    if trigger_type:
        filtered_triggers = {
            k: v
            for k, v in REMEDIATION_REGISTRY.items()
            if v.get("trigger_type") == trigger_type
        }
        logger.info(
            f"{Colors.CYAN}Found {len(filtered_triggers)} triggers of type '{trigger_type}'{Colors.RESET}"
        )
        return filtered_triggers

    logger.info(
        f"{Colors.CYAN}Found {len(REMEDIATION_REGISTRY)} total triggers in registry{Colors.RESET}"
    )
    return REMEDIATION_REGISTRY


def get_trigger_info(trigger: str) -> Optional[Dict[str, Any]]:
    """Get detailed information about a trigger.

    This function returns the complete registry entry for a given trigger,
    including the function reference, priority, compliance frameworks, and safety mode.

    Args:
        trigger: The trigger name (Config rule name or EventBridge pattern).

    Returns:
        The registry entry if found, None otherwise.

    Example:
        >>> info = get_trigger_info("s3-bucket-public-read-prohibited")
        >>> print(info)
        {
            'function': <function block_s3_public_access at 0x...>,
            'trigger_type': 'CONFIG_RULE',
            'priority': 'CRITICAL',
            'compliance_frameworks': ['PCI-DSS-1.3.2', 'SOC2-CC6.6', 'CIS-2.1.1'],
            'safety_mode': 'AUTO'
        }
    """
    registry_entry = REMEDIATION_REGISTRY.get(trigger)

    if not registry_entry:
        logger.warning(
            f"{Colors.YELLOW}No registry entry found for trigger: {trigger}{Colors.RESET}"
        )
        return None

    # Create a copy without the function reference for logging
    info_copy = {
        "trigger": trigger,
        "trigger_type": registry_entry.get("trigger_type"),
        "priority": registry_entry.get("priority"),
        "compliance_frameworks": registry_entry.get("compliance_frameworks"),
        "safety_mode": registry_entry.get("safety_mode"),
        "function_name": (
            registry_entry.get("function").__name__
            if registry_entry.get("function")
            else None
        ),
    }

    logger.info(f"{Colors.CYAN}Trigger info: {trigger}{Colors.RESET}")
    for key, value in info_copy.items():
        logger.info(f"  {key}: {value}")

    return registry_entry
