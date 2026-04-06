# CloudFormation Template Validation Script

This document describes the CloudFormation validation script for the AWS GRC Evidence Collector project.

## Overview

The [`validate_cloudformation.py`](validate_cloudformation.py) script provides comprehensive validation of CloudFormation templates through three steps:

1. **YAML Syntax Validation** - Validates YAML syntax using PyYAML (handles CloudFormation-specific tags gracefully)
2. **cfn-lint Validation** - Validates CloudFormation best practices and potential issues using cfn-lint
3. **AWS CloudFormation Validation** - Validates templates against AWS CloudFormation service requirements

## Usage

### Basic Usage

```bash
# Validate the first available template (grc-collector-template.yaml)
python validate_cloudformation.py

# Validate a specific template
python validate_cloudformation.py cloudformation/grc-collector-template.yaml
python validate_cloudformation.py cloudformation/grc-platform-template.yaml
python validate_cloudformation.py cloudformation/iam-roles-template.yaml
python validate_cloudformation.py cloudformation/monitoring-template.yaml
```

### With Verbose Output

```bash
python validate_cloudformation.py -v
python validate_cloudformation.py --verbose
```

### Help

```bash
python validate_cloudformation.py --help
```

## Exit Codes

- `0` - All validations passed
- `1` - One or more validations failed
- `2` - Invalid arguments or file not found
- `3` - AWS credentials not configured (if AWS validation is required)

## Requirements

The script uses the following dependencies from the project's [`requirements.txt`](requirements.txt):

- `boto3>=1.34.0` - For AWS CloudFormation validation
- `cfn-lint>=0.85.0` - For CloudFormation linting (optional, skips if not available)
- `pyyaml` - For YAML syntax validation (optional, skips if not available)

### Installing Dependencies

```bash
pip install -r requirements.txt
```

If PyYAML is not in requirements.txt, you can install it separately:

```bash
pip install pyyaml
```

## AWS Credentials

For AWS CloudFormation validation, you need to configure AWS credentials:

```bash
# Using AWS CLI
aws configure

# Or set environment variables
set AWS_ACCESS_KEY_ID=your_access_key
set AWS_SECRET_ACCESS_KEY=your_secret_key
set AWS_DEFAULT_REGION=us-east-1
```

## Validation Steps

### Step 1: YAML Syntax Validation

Validates the YAML syntax of the template. CloudFormation templates use custom YAML tags (like `!Equals`, `!Sub`, `!Ref`) that PyYAML doesn't recognize by default. The script handles this gracefully and treats CloudFormation-specific tags as valid.

**Output:**
- `[PASS]` - YAML syntax is valid
- `[WARN]` - YAML appears valid (contains CloudFormation-specific tags)
- `[FAIL]` - YAML syntax error detected

### Step 2: cfn-lint Validation

Validates CloudFormation best practices and potential issues using cfn-lint. This step is optional and will be skipped if cfn-lint is not installed.

**Output:**
- `[PASS]` - No issues found
- `[FAIL]` - Issues found (displays up to 10 errors)

### Step 3: AWS CloudFormation Validation

Validates the template against AWS CloudFormation service requirements using the `validate_template` API. This step requires AWS credentials.

**Output:**
- `[PASS]` - Template is valid
- `[FAIL]` - Template validation error
- `[WARN]` - AWS validation skipped (credentials not configured)

**Note:** The AWS CloudFormation `validate_template` API has a 51,200 byte limit. Large templates (like `grc-platform-template.yaml`) may fail this validation even if they are syntactically correct.

## Example Output

### Successful Validation

```
======================================================================
CloudFormation Template Validation: grc-collector-template.yaml
======================================================================

Step 1: YAML Syntax Validation
[WARN]: YAML syntax appears valid (contains CloudFormation-specific tags)
[INFO]: CloudFormation-specific tags will be validated by cfn-lint and AWS

Step 2: cfn-lint Validation
[PASS]: cfn-lint validation passed (no issues found)

Step 3: AWS CloudFormation Validation
[INFO]: Validating template with AWS CloudFormation...
[PASS]: AWS CloudFormation validation passed
[INFO]:   Description: AWS GRC Evidence Collector with optional Bedrock AI Analysis...
[INFO]:   Parameters: 15
[INFO]:   Resource Types: 0

======================================================================
Validation Summary
======================================================================

[ALL VALIDATIONS PASSED]
[INFO]: Template: cloudformation\grc-collector-template.yaml
```

### Failed Validation

```
======================================================================
CloudFormation Template Validation: iam-roles-template.yaml
======================================================================

Step 1: YAML Syntax Validation
[WARN]: YAML syntax appears valid (contains CloudFormation-specific tags)
[INFO]: CloudFormation-specific tags will be validated by cfn-lint and AWS

Step 2: cfn-lint Validation
[PASS]: cfn-lint validation passed (no issues found)

Step 3: AWS CloudFormation Validation
[INFO]: Validating template with AWS CloudFormation...
[FAIL]: AWS CloudFormation validation error: Template format error: Unresolved dependencies [AlertTopic]. Cannot reference resources in the Conditions block of the template

======================================================================
Validation Summary
======================================================================

[VALIDATION FAILED]
[INFO]: Template: cloudformation\iam-roles-template.yaml
[INFO]: Total errors: 1

Error Details:
  1. AWS CloudFormation validation error: Template format error: Unresolved dependencies [AlertTopic]. Cannot reference resources in the Conditions block of the template
```

## Platform Compatibility

The script is designed to work on:
- **Windows** (cmd.exe, PowerShell)
- **macOS**
- **Linux**

The script automatically handles Unicode character encoding issues on Windows by falling back to ASCII-compatible characters when needed.

## Integration with CI/CD

You can integrate this script into your CI/CD pipeline to validate CloudFormation templates before deployment:

### GitHub Actions Example

```yaml
name: Validate CloudFormation Templates

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pyyaml
      - name: Validate templates
        run: |
          python validate_cloudformation.py cloudformation/grc-collector-template.yaml
          python validate_cloudformation.py cloudformation/monitoring-template.yaml
```

### Makefile Integration

You can add validation targets to your [`Makefile`](Makefile):

```makefile
.PHONY: validate-cfn
validate-cfn:
	python validate_cloudformation.py cloudformation/grc-collector-template.yaml
	python validate_cloudformation.py cloudformation/monitoring-template.yaml
```

Then run:

```bash
make validate-cfn
```

## Troubleshooting

### PyYAML Not Available

If you see `[WARN]: PyYAML not available, skipping YAML syntax validation`, install PyYAML:

```bash
pip install pyyaml
```

### cfn-lint Not Available

If you see `[WARN]: cfn-lint not available, skipping cfn-lint validation`, install cfn-lint:

```bash
pip install cfn-lint
```

### AWS Credentials Not Configured

If you see `[WARN]: AWS validation skipped (credentials not configured)`, configure AWS credentials:

```bash
aws configure
```

### Template Too Large for AWS Validation

If you see an error about template size exceeding 51,200 bytes, this is a limitation of the AWS CloudFormation `validate_template` API. The template may still be valid, but you'll need to deploy it to verify.

### Unicode Encoding Errors on Windows

The script automatically handles Unicode encoding errors by falling back to ASCII-compatible characters. If you still see encoding issues, try running the script in PowerShell instead of cmd.exe.

## Additional Resources

- [AWS CloudFormation Template Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-reference.html)
- [cfn-lint Documentation](https://github.com/aws-cloudformation/cfn-lint)
- [AWS CloudFormation Limits](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html)
