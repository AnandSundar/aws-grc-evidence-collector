#!/usr/bin/env python3
"""
CloudFormation Template Validator

This script performs basic validation on CloudFormation templates
to catch common YAML syntax issues before deployment.

Usage:
    python scripts/validate_templates.py
"""

import sys
from pathlib import Path

def validate_template_structure(template_path):
    """Validate basic YAML structure."""
    print(f"Validating {template_path}...")

    try:
        content = Path(template_path).read_text()

        # Check for common YAML issues
        issues = []

        # Check for tab characters (YAML doesn't allow tabs for indentation)
        if '\t' in content:
            issues.append("Contains tab characters (use spaces for indentation)")

        # Check for trailing spaces
        lines_with_trailing_spaces = []
        for i, line in enumerate(content.split('\n'), 1):
            if line.rstrip() != line and line.strip():
                lines_with_trailing_spaces.append(i)
        if lines_with_trailing_spaces:
            issues.append(f"Lines with trailing spaces: {lines_with_trailing_spaces[:5]}...")

        # Check for inconsistent indentation around IAM statements
        if '- Sid:' in content:
            # Look for potential alignment issues
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if '- Sid:' in line:
                    # Check next few lines for proper indentation
                    if i + 1 < len(lines) and 'Effect:' in lines[i + 1]:
                        current_indent = len(line) - len(line.lstrip())
                        next_indent = len(lines[i + 1]) - len(lines[i + 1].lstrip())
                        if abs(next_indent - current_indent) > 4:
                            issues.append(f"Possible indentation issue around line {i + 1}")

        if issues:
            print(f"  [FAIL] Issues found:")
            for issue in issues:
                print(f"    - {issue}")
            return False
        else:
            print(f"  [PASS] Basic validation passed")
            return True

    except FileNotFoundError:
        print(f"  [ERROR] File not found: {template_path}")
        return False
    except Exception as e:
        print(f"  [ERROR] Validation error: {e}")
        return False

def main():
    """Main validation function."""
    print("\n" + "="*60)
    print("CloudFormation Template Validator")
    print("="*60 + "\n")

    templates = [
        "cloudformation/grc-platform-template.yaml",
        "cloudformation/grc-collector-template.yaml",
        "cloudformation/iam-roles-template.yaml",
        "cloudformation/monitoring-template.yaml"
    ]

    all_passed = True
    for template in templates:
        if not validate_template_structure(template):
            all_passed = False

    print("\n" + "="*60)
    if all_passed:
        print("[SUCCESS] All templates passed basic validation")
        print("\nYou can now deploy with:")
        print("  python scripts/deploy_cloudformation.py --update")
        return 0
    else:
        print("[FAILED] Some templates have issues that need fixing")
        print("\nPlease review the errors above before deploying.")
        return 1

if __name__ == "__main__":
    sys.exit(main())