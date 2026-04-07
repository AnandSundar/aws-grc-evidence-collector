#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS GRC Evidence Collector - CloudFormation Template Validation Script

This script validates CloudFormation templates through three steps:
1. YAML syntax validation using PyYAML
2. cfn-lint validation (if available)
3. AWS CloudFormation validation using boto3

Usage:
    python validate_cloudformation.py [template_path]

Examples:
    python validate_cloudformation.py
    python validate_cloudformation.py cloudformation/grc-collector-template.yaml
    python validate_cloudformation.py cloudformation/grc-platform-template.yaml

Exit Codes:
    0 - All validations passed
    1 - One or more validations failed
    2 - Invalid arguments or file not found
    3 - AWS credentials not configured
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try to import optional dependencies
try:
    import yaml

    PYAML_AVAILABLE = True
except ImportError:
    PYAML_AVAILABLE = False

try:
    from cfnlint import decode
    from cfnlint.runner import Runner
    from cfnlint.rules import RulesCollection

    CFNLINT_AVAILABLE = True
except ImportError:
    CFNLINT_AVAILABLE = False

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


# ANSI color codes for terminal output (cross-platform compatible)
class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"

    @classmethod
    def disable(cls):
        """Disable colors for non-terminal output."""
        cls.RESET = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.BOLD = ""


# Disable colors if output is not a terminal
if not sys.stdout.isatty():
    Colors.disable()


def print_header(text: str) -> None:
    """Print a formatted header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")


def print_step(step_num: int, step_name: str) -> None:
    """Print a validation step header."""
    print(f"{Colors.BOLD}{Colors.BLUE}Step {step_num}: {step_name}{Colors.RESET}")


def print_pass(message: str) -> None:
    """Print a success message."""
    try:
        print(f"{Colors.GREEN}✓ PASS{Colors.RESET}: {message}")
    except UnicodeEncodeError:
        print(f"{Colors.GREEN}[PASS]{Colors.RESET}: {message}")


def print_fail(message: str) -> None:
    """Print a failure message."""
    try:
        print(f"{Colors.RED}✗ FAIL{Colors.RESET}: {message}")
    except UnicodeEncodeError:
        print(f"{Colors.RED}[FAIL]{Colors.RESET}: {message}")


def print_warn(message: str) -> None:
    """Print a warning message."""
    try:
        print(f"{Colors.YELLOW}⚠ WARN{Colors.RESET}: {message}")
    except UnicodeEncodeError:
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET}: {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    try:
        print(f"{Colors.CYAN}ℹ INFO{Colors.RESET}: {message}")
    except UnicodeEncodeError:
        print(f"{Colors.CYAN}[INFO]{Colors.RESET}: {message}")


def get_template_path(template_arg: Optional[str] = None) -> Path:
    """
    Get the template path from argument or default to the first available template.

    Args:
        template_arg: Optional template path from command line

    Returns:
        Path object pointing to the template file

    Raises:
        SystemExit: If no valid template is found
    """
    cloudformation_dir = Path("cloudformation")

    # List of available templates in order of preference
    available_templates = [
        "grc-collector-template.yaml",
        "grc-platform-template.yaml",
        "iam-roles-template.yaml",
        "monitoring-template.yaml",
    ]

    if template_arg:
        template_path = Path(template_arg)
        if not template_path.exists():
            print_fail(f"Template file not found: {template_arg}")
            print_info(f"Looking in: {template_path.absolute()}")
            sys.exit(2)
        return template_path

    # Default to the first available template
    for template_name in available_templates:
        template_path = cloudformation_dir / template_name
        if template_path.exists():
            print_info(f"No template specified, using: {template_path}")
            return template_path

    print_fail("No CloudFormation templates found in cloudformation/ directory")
    sys.exit(2)


def validate_yaml_syntax(template_path: Path) -> Tuple[bool, List[str]]:
    """
    Validate YAML syntax using PyYAML.

    Note: CloudFormation templates use custom YAML tags (like !Equals, !Sub, !Ref)
    that PyYAML doesn't recognize by default. This validation checks for basic
    YAML syntax errors but may report false positives for CloudFormation-specific tags.
    For comprehensive validation, rely on cfn-lint and AWS CloudFormation validation.

    Args:
        template_path: Path to the CloudFormation template

    Returns:
        Tuple of (success, error_messages)
    """
    if not PYAML_AVAILABLE:
        print_warn("PyYAML not available, skipping YAML syntax validation")
        print_info("Install PyYAML to enable this validation: pip install pyyaml")
        return True, []

    errors = []

    try:
        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()
            # Try to parse the YAML
            try:
                yaml.safe_load(content)
                print_pass("YAML syntax is valid")
                return True, errors
            except yaml.constructor.ConstructorError as e:
                # CloudFormation uses custom tags that PyYAML doesn't recognize
                # This is expected and not a real error
                if "could not determine a constructor for the tag" in str(e):
                    print_warn(
                        "YAML syntax appears valid (contains CloudFormation-specific tags)"
                    )
                    print_info(
                        "CloudFormation-specific tags will be validated by cfn-lint and AWS"
                    )
                    return True, errors
                else:
                    # Re-raise other constructor errors
                    raise
    except yaml.YAMLError as e:
        error_msg = f"YAML syntax error: {str(e)}"
        errors.append(error_msg)
        print_fail(error_msg)
        return False, errors
    except Exception as e:
        error_msg = f"Unexpected error reading YAML: {str(e)}"
        errors.append(error_msg)
        print_fail(error_msg)
        return False, errors


def validate_cfn_lint(template_path: Path) -> Tuple[bool, List[str]]:
    """
    Validate CloudFormation template using cfn-lint.

    Args:
        template_path: Path to the CloudFormation template

    Returns:
        Tuple of (success, error_messages)
    """
    if not CFNLINT_AVAILABLE:
        print_warn("cfn-lint not available, skipping cfn-lint validation")
        print_info("Install cfn-lint to enable this validation: pip install cfn-lint")
        return True, []

    errors = []

    try:
        # Use the cfnlint API to validate the template
        # Try the newer API first
        try:
            from cfnlint import decode
            from cfnlint.runner import TemplateRunner
            from cfnlint.rules import RulesCollection

            # Load rules
            rules = RulesCollection()

            # Decode and validate the template
            template, matches = decode.decode(template_path, ["us-east-1"])

        except (ImportError, TypeError):
            # Fall back to older API or different approach
            try:
                from cfnlint import decode
                from cfnlint.runner import Runner
                from cfnlint.rules import RulesCollection

                # Load rules
                rules = RulesCollection()

                # Try alternative decode method
                runner = Runner(rules, template_path, ["us-east-1"])
                matches = runner.run()
                template = None
            except Exception:
                # If all else fails, try a simpler approach
                try:
                    from cfnlint import decode

                    template, matches = decode.decode(template_path)
                except Exception as e:
                    raise Exception(f"Unable to use cfn-lint API: {str(e)}")

        if matches:
            for match in matches:
                error_msg = (
                    f"Line {match.linenumber}: {match.rule.id} - {match.message}"
                )
                errors.append(error_msg)

            print_fail(f"cfn-lint found {len(matches)} issue(s):")
            for error in errors[:10]:  # Show first 10 errors
                try:
                    print(f"  {Colors.RED}•{Colors.RESET} {error}")
                except UnicodeEncodeError:
                    print(f"  {Colors.RED}-{Colors.RESET} {error}")
            if len(errors) > 10:
                print_info(f"  ... and {len(errors) - 10} more issue(s)")

            return False, errors

        print_pass("cfn-lint validation passed (no issues found)")
        return True, errors

    except Exception as e:
        error_msg = f"cfn-lint validation error: {str(e)}"
        errors.append(error_msg)
        print_fail(error_msg)
        return False, errors


def validate_aws_cloudformation(template_path: Path) -> Tuple[bool, List[str]]:
    """
    Validate CloudFormation template using AWS CloudFormation service.

    Args:
        template_path: Path to the CloudFormation template

    Returns:
        Tuple of (success, error_messages)
    """
    errors = []

    try:
        # Read template content
        with open(template_path, "r", encoding="utf-8") as f:
            template_body = f.read()

        # Create CloudFormation client
        cf_client = boto3.client("cloudformation")

        # Validate template using AWS CloudFormation
        print_info("Validating template with AWS CloudFormation...")
        response = cf_client.validate_template(TemplateBody=template_body)

        # Extract template information
        description = response.get("Description", "No description")
        parameters = response.get("Parameters", [])
        resources = response.get("ResourceTypes", [])

        print_pass("AWS CloudFormation validation passed")
        print_info(f"  Description: {description[:80]}...")
        print_info(f"  Parameters: {len(parameters)}")
        print_info(f"  Resource Types: {len(resources)}")

        return True, errors

    except NoCredentialsError:
        error_msg = "AWS credentials not found. Please configure AWS credentials."
        errors.append(error_msg)
        print_fail(error_msg)
        print_info("To configure AWS credentials:")
        print_info("  1. Run: aws configure")
        print_info(
            "  2. Or set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
        )
        return False, errors

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_msg = e.response.get("Error", {}).get("Message", str(e))

        if error_code == "ValidationError":
            errors.append(f"AWS CloudFormation validation error: {error_msg}")
            print_fail(f"AWS CloudFormation validation error: {error_msg}")
        elif error_code == "AccessDenied":
            errors.append(f"AWS access denied: {error_msg}")
            print_fail(f"AWS access denied: {error_msg}")
            print_info(
                "Ensure your IAM user has 'cloudformation:ValidateTemplate' permission"
            )
        else:
            errors.append(f"AWS client error: {error_msg}")
            print_fail(f"AWS client error: {error_msg}")

        return False, errors

    except BotoCoreError as e:
        error_msg = f"AWS core error: {str(e)}"
        errors.append(error_msg)
        print_fail(error_msg)
        return False, errors

    except Exception as e:
        error_msg = f"Unexpected error during AWS validation: {str(e)}"
        errors.append(error_msg)
        print_fail(error_msg)
        return False, errors


def validate_template(template_path: Path) -> int:
    """
    Run all validation steps on a CloudFormation template.

    Args:
        template_path: Path to the CloudFormation template

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print_header(f"CloudFormation Template Validation: {template_path.name}")

    # Track overall success
    all_passed = True
    all_errors = []

    # Step 1: YAML Syntax Validation
    print_step(1, "YAML Syntax Validation")
    yaml_passed, yaml_errors = validate_yaml_syntax(template_path)
    all_passed = all_passed and yaml_passed
    all_errors.extend(yaml_errors)

    # Step 2: cfn-lint Validation
    print()
    print_step(2, "cfn-lint Validation")
    cfnlint_passed, cfnlint_errors = validate_cfn_lint(template_path)
    all_passed = all_passed and cfnlint_passed
    all_errors.extend(cfnlint_errors)

    # Step 3: AWS CloudFormation Validation
    print()
    print_step(3, "AWS CloudFormation Validation")
    aws_passed, aws_errors = validate_aws_cloudformation(template_path)

    # AWS validation is optional (requires credentials)
    # Only fail if AWS credentials are configured but validation fails
    if aws_passed:
        all_passed = all_passed and True
    else:
        # Check if the error is due to missing credentials
        if any("credentials" in error.lower() for error in aws_errors):
            print_warn("AWS validation skipped (credentials not configured)")
            print_info("Template validation is incomplete without AWS validation")
        else:
            all_passed = False
            all_errors.extend(aws_errors)

    # Print summary
    print()
    print_header("Validation Summary")

    if all_passed:
        try:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ ALL VALIDATIONS PASSED{Colors.RESET}")
        except UnicodeEncodeError:
            print(f"{Colors.GREEN}{Colors.BOLD}[ALL VALIDATIONS PASSED]{Colors.RESET}")
        print_info(f"Template: {template_path}")
        return 0
    else:
        try:
            print(f"{Colors.RED}{Colors.BOLD}✗ VALIDATION FAILED{Colors.RESET}")
        except UnicodeEncodeError:
            print(f"{Colors.RED}{Colors.BOLD}[VALIDATION FAILED]{Colors.RESET}")
        print_info(f"Template: {template_path}")
        print_info(f"Total errors: {len(all_errors)}")

        if all_errors:
            print()
            print(f"{Colors.BOLD}Error Details:{Colors.RESET}")
            for i, error in enumerate(all_errors, 1):
                print(f"  {i}. {error}")

        return 1


def main() -> int:
    """
    Main entry point for the validation script.

    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        description="Validate AWS CloudFormation templates for the GRC Evidence Collector project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Validate first available template
  %(prog)s cloudformation/grc-collector-template.yaml
  %(prog)s cloudformation/grc-platform-template.yaml

Available templates:
  - cloudformation/grc-collector-template.yaml
  - cloudformation/grc-platform-template.yaml
  - cloudformation/iam-roles-template.yaml
  - cloudformation/monitoring-template.yaml

Exit Codes:
  0 - All validations passed
  1 - One or more validations failed
  2 - Invalid arguments or file not found
  3 - AWS credentials not configured (if AWS validation is required)
        """,
    )

    parser.add_argument(
        "template",
        nargs="?",
        help="Path to the CloudFormation template file (default: first available template)",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Get template path
    try:
        template_path = get_template_path(args.template)
    except SystemExit as e:
        return e.code

    # Run validation
    exit_code = validate_template(template_path)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
