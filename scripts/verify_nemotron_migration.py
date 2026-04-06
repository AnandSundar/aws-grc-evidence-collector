#!/usr/bin/env python3
"""
Nemotron Migration Verification Script

This script verifies that the NVIDIA Nemotron Nano 12B v2 model
migration from Anthropic Claude 3 Sonnet is correctly configured
and deployed.

Usage:
    python scripts/verify_nemotron_migration.py
"""

import json
import sys
import re
from pathlib import Path

# Colors for terminal output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_status(message, status):
    """Print status message with color."""
    if status == "pass":
        print(f"{Colors.GREEN}[PASS]{Colors.RESET} {message}")
    elif status == "fail":
        print(f"{Colors.RED}[FAIL]{Colors.RESET} {message}")
    elif status == "warn":
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {message}")
    elif status == "info":
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} {message}")


def check_file_contains(file_path, patterns, description):
    """Check if file contains expected patterns."""
    try:
        content = Path(file_path).read_text()
        passed = True

        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                print_status(f"{description}: Found '{pattern}'", "pass")
            else:
                print_status(f"{description}: Missing '{pattern}'", "fail")
                passed = False

        return passed
    except FileNotFoundError:
        print_status(f"{description}: File not found - {file_path}", "fail")
        return False
    except Exception as e:
        print_status(f"{description}: Error reading file - {e}", "fail")
        return False


def check_file_excludes(file_path, patterns, description):
    """Check if file does NOT contain old patterns."""
    try:
        content = Path(file_path).read_text()
        passed = True

        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                print_status(f"{description}: Found old pattern '{pattern}'", "fail")
                passed = False
            else:
                print_status(f"{description}: Correctly removed '{pattern}'", "pass")

        return passed
    except FileNotFoundError:
        print_status(f"{description}: File not found - {file_path}", "warn")
        return True  # Don't fail if file doesn't exist
    except Exception as e:
        print_status(f"{description}: Error reading file - {e}", "fail")
        return False


def verify_lambda_functions():
    """Verify Lambda function code uses Nemotron."""
    print_status("\n=== Verifying Lambda Functions ===", "info")

    lambda_files = [
        "lambda/handler_ai.py",
        "lambda/evidence_processor/handler_ai.py"
    ]

    all_passed = True

    for lambda_file in lambda_files:
        print_status(f"\nChecking {lambda_file}:", "info")

        # Check for Nemotron model ID
        if not check_file_contains(
            lambda_file,
            [r"nvidia\.nemotron-nano-12b-v2"],
            "Model ID"
        ):
            all_passed = False

        # Check for Nemotron request format
        if not check_file_contains(
            lambda_file,
            [r"max_gen_len", r"results\[0\]\.sequence"],
            "Nemotron API format"
        ):
            all_passed = False

        # Check for old Claude references
        if not check_file_excludes(
            lambda_file,
            [r"anthropic\.claude-3-sonnet", r"content\[0\]\.text"],
            "Old Claude patterns"
        ):
            all_passed = False

    return all_passed


def verify_cloudformation_templates():
    """Verify CloudFormation templates use Nemotron."""
    print_status("\n=== Verifying CloudFormation Templates ===", "info")

    template_files = [
        "cloudformation/grc-platform-template.yaml",
        "cloudformation/grc-collector-template.yaml",
        "cloudformation/iam-roles-template.yaml"
    ]

    all_passed = True

    for template_file in template_files:
        print_status(f"\nChecking {template_file}:", "info")

        # Check for Nemotron model ID
        if not check_file_contains(
            template_file,
            [r"nvidia\.nemotron-nano-12b-v2"],
            "Model ID"
        ):
            all_passed = False

        # Check for Nemotron IAM permissions
        if not check_file_contains(
            template_file,
            [r"bedrock:InvokeModel"],
            "Bedrock IAM permissions"
        ):
            all_passed = False

        # Check for old Claude references
        if not check_file_excludes(
            template_file,
            [r"anthropic\.claude-3-sonnet"],
            "Old Claude patterns"
        ):
            all_passed = False

    return all_passed


def verify_configuration_files():
    """Verify configuration files use Nemotron."""
    print_status("\n=== Verifying Configuration Files ===", "info")

    config_files = [
        ".env.example"
    ]

    all_passed = True

    for config_file in config_files:
        print_status(f"\nChecking {config_file}:", "info")

        # Check for Nemotron model ID
        if not check_file_contains(
            config_file,
            [r"nvidia\.nemotron-nano-12b-v2"],
            "Model ID"
        ):
            all_passed = False

        # Check for old Claude references
        if not check_file_excludes(
            config_file,
            [r"anthropic\.claude-3-sonnet"],
            "Old Claude patterns"
        ):
            all_passed = False

    return all_passed


def verify_documentation():
    """Verify documentation is updated."""
    print_status("\n=== Verifying Documentation ===", "info")

    # Check key documentation files for Nemotron references
    doc_files = [
        ("README.md", [r"nemotron", r"nvidia"], [r"anthropic\.claude-3-sonnet"]),
        ("docs/README.md", [r"nemotron", r"nvidia"], [r"anthropic\.claude-3-sonnet"])
    ]

    all_passed = True

    for doc_file, required_patterns, excluded_patterns in doc_files:
        print_status(f"\nChecking {doc_file}:", "info")

        # Check for Nemotron references
        if not check_file_contains(doc_file, required_patterns, "Nemotron references"):
            all_passed = False

        # Warn if old Claude references still exist
        if not check_file_excludes(doc_file, excluded_patterns, "Old Claude patterns"):
            print_status("Documentation may still reference old model - update manually", "warn")

    return all_passed


def main():
    """Main verification function."""
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Nemotron Migration Verification{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

    results = {
        "Lambda Functions": verify_lambda_functions(),
        "CloudFormation Templates": verify_cloudformation_templates(),
        "Configuration Files": verify_configuration_files(),
        "Documentation": verify_documentation()
    }

    # Summary
    print_status("\n=== Verification Summary ===", "info")
    print()

    all_passed = True
    for component, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        color = Colors.GREEN if passed else Colors.RED
        print(f"{color}{component}: {status}{Colors.RESET}")
        if not passed:
            all_passed = False

    print()
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    if all_passed:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ All checks passed!{Colors.RESET}")
        print(f"{Colors.GREEN}Nemotron migration is correctly configured.{Colors.RESET}")
        print()
        print("Next steps:")
        print("1. Deploy the updated CloudFormation stack:")
        print("   python scripts/deploy_cloudformation.py --update")
        print()
        print("2. Test AI analysis with a sample event:")
        print("   aws lambda invoke --function-name grc-evidence-platform-evidence-processor-dev \\")
        print("     --payload '{\"test\": true}' response.json")
        print()
        print("3. Verify AI analysis in CloudWatch logs:")
        print("   aws logs tail /aws/lambda/grc-evidence-platform-evidence-processor-dev --follow")
        return 0
    else:
        print(f"{Colors.RED}{Colors.BOLD}✗ Some checks failed!{Colors.RESET}")
        print(f"{Colors.RED}Please review and fix the issues above.{Colors.RESET}")
        print()
        print("Common fixes:")
        print("1. Ensure all Lambda files use nvidia.nemotron-nano-12b-v2")
        print("2. Verify CloudFormation templates have correct model ID")
        print("3. Update any remaining Claude references in code")
        print("4. Run: git diff to see all changes made")
        return 1


if __name__ == "__main__":
    sys.exit(main())