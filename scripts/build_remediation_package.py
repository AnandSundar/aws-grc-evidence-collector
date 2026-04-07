#!/usr/bin/env python3
"""
Remediation Lambda Package Builder

Builds deployment packages for the remediation engine Lambda function,
including all remediation modules and dependencies.

Usage:
    python scripts/build_remediation_package.py [--upload] [--bucket BUCKET_NAME]

Author: GRC Platform Team
Version: 2.0
"""

import argparse
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime
import boto3
from botocore.exceptions import ClientError


class Colors:
    """ANSI color codes for terminal output."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_colored(message: str, color: str = Colors.RESET) -> None:
    """Print a colored message to the terminal."""
    print(f"{color}{message}{Colors.RESET}")


def print_success(message: str) -> None:
    """Print a success message in green."""
    print_colored(f"[OK] {message}", Colors.GREEN)


def print_error(message: str) -> None:
    """Print an error message in red."""
    print_colored(f"[ERROR] {message}", Colors.RED)


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    print_colored(f"[WARN] {message}", Colors.YELLOW)


def print_info(message: str) -> None:
    """Print an info message in cyan."""
    print_colored(f"[INFO] {message}", Colors.CYAN)


def print_header(message: str) -> None:
    """Print a header message in bold blue."""
    print_colored(f"\n{'=' * 70}", Colors.BLUE + Colors.BOLD)
    print_colored(message, Colors.BOLD + Colors.BLUE)
    print_colored(f"{'=' * 70}\n", Colors.BLUE)


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def create_deployment_package(
    output_path: str = None,
    include_tests: bool = False
) -> dict:
    """Create Lambda deployment package for remediation engine.

    Args:
        output_path: Path for output zip file. If None, uses default.
        include_tests: Whether to include test files (default: False)

    Returns:
        Dictionary with package info: path, size, file_count, etc.
    """
    project_root = get_project_root()
    remediation_engine_dir = project_root / "lambda" / "remediation_engine"
    remediations_dir = project_root / "remediations"

    # Default output path
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = str(project_root / "build" / f"remediation-engine-{timestamp}.zip")

    # Create output directory if needed
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print_header("Creating Remediation Engine Lambda Package")
    print_info(f"Project root: {project_root}")
    print_info(f"Output path: {output_path}")
    print_info(f"Include tests: {include_tests}")

    # Create temporary directory for package contents
    with tempfile.TemporaryDirectory() as temp_dir:
        print_info(f"Building package in: {temp_dir}")

        # Track package statistics
        file_count = 0
        total_size = 0

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # 1. Add main Lambda handler (lambda_function.py)
            lambda_handler_path = remediation_engine_dir / "lambda_function.py"
            if lambda_handler_path.exists():
                zipf.write(lambda_handler_path, "lambda_function.py")
                file_count += 1
                total_size += lambda_handler_path.stat().st_size
                print_success(f"Added: lambda_function.py")
            else:
                print_error(f"Required file not found: {lambda_handler_path}")
                raise FileNotFoundError(f"Lambda handler not found: {lambda_handler_path}")

            # 2. Add all remediation modules
            if remediations_dir.exists():
                for root, dirs, files in os.walk(remediations_dir):
                    # Skip test files and __pycache__ unless explicitly included
                    if not include_tests:
                        dirs[:] = [d for d in dirs if d != '__pycache__']
                        files = [f for f in files if not f.startswith('test_') and not f.endswith('.pyc')]

                    for file in files:
                        if file.endswith('.py'):
                            file_path = Path(root) / file
                            arcname = f"remediations/{file_path.relative_to(remediations_dir)}"
                            zipf.write(file_path, arcname)
                            file_count += 1
                            total_size += file_path.stat().st_size
                            print_success(f"Added: {arcname}")

                print_success(f"Total remediation modules: {file_count - 1}")
            else:
                print_error(f"Remediations directory not found: {remediations_dir}")
                raise FileNotFoundError(f"Remediations directory not found: {remediations_dir}")

        # Get final package size
        package_size = os.path.getsize(output_path)

        print_header("Package Build Complete")
        print_success(f"Package created: {output_path}")
        print_info(f"Files included: {file_count}")
        print_info(f"Source size: {total_size:,} bytes ({total_size / 1024:.1f} KB)")
        print_info(f"Package size: {package_size:,} bytes ({package_size / 1024:.1f} KB)")
        print_info(f"Compression ratio: {(1 - package_size / total_size) * 100:.1f}%")

        # Validate package size
        MAX_COMPRESSED_SIZE = 50 * 1024 * 1024  # 50MB
        MAX_UNCOMPRESSED_SIZE = 250 * 1024 * 1024  # 250MB

        if package_size > MAX_COMPRESSED_SIZE:
            print_warning(f"Package size ({package_size / 1024 / 1024:.1f} MB) exceeds recommended limit ({MAX_COMPRESSED_SIZE / 1024 / 1024} MB)")
            print_warning("Consider using S3 deployment or reducing package size")

        if package_size > MAX_UNCOMPRESSED_SIZE:
            print_error(f"Package size ({package_size / 1024 / 1024:.1f} MB) exceeds Lambda limit ({MAX_UNCOMPRESSED_SIZE / 1024 / 1024} MB)")
            raise ValueError("Package size exceeds Lambda limits")

        if package_size < MAX_COMPRESSED_SIZE * 0.8:
            print_success(f"Package size well within limits ({package_size / MAX_COMPRESSED_SIZE * 100:.1f}% of max)")

        return {
            "path": output_path,
            "size": package_size,
            "file_count": file_count,
            "compression_ratio": (1 - package_size / total_size) * 100 if total_size > 0 else 0
        }


def upload_to_s3(
    package_path: str,
    bucket_name: str,
    key_prefix: str = None
) -> dict:
    """Upload deployment package to S3.

    Args:
        package_path: Path to package zip file
        bucket_name: S3 bucket name
        key_prefix: Optional key prefix for S3 object

    Returns:
        Dictionary with upload info: bucket, key, version_id, etc.
    """
    print_header("Uploading Package to S3")

    # Generate S3 key
    filename = os.path.basename(package_path)
    if key_prefix:
        s3_key = f"{key_prefix}/{filename}"
    else:
        s3_key = f"remediation-engine/{filename}"

    print_info(f"Bucket: {bucket_name}")
    print_info(f"Key: {s3_key}")
    print_info(f"File: {package_path}")

    try:
        s3_client = boto3.client('s3')

        # Upload file
        print_info("Uploading to S3...")
        s3_client.upload_file(package_path, bucket_name, s3_key)

        # Get object info
        response = s3_client.head_object(Bucket=bucket_name, Key=s3_key)
        version_id = response.get('VersionId', 'null')
        size = response.get('ContentLength', 0)
        etag = response.get('ETag', '').strip('"')

        print_success(f"Upload complete!")
        print_info(f"Version ID: {version_id}")
        print_info(f"Size: {size:,} bytes")
        print_info(f"ETag: {etag}")
        print_info(f"S3 URI: s3://{bucket_name}/{s3_key}")

        return {
            "bucket": bucket_name,
            "key": s3_key,
            "version_id": version_id,
            "size": size,
            "etag": etag,
            "s3_uri": f"s3://{bucket_name}/{s3_key}"
        }

    except ClientError as e:
        print_error(f"Failed to upload to S3: {e}")
        raise


def validate_package_structure(package_path: str) -> bool:
    """Validate that package has all required files.

    Args:
        package_path: Path to package zip file

    Returns:
        True if package is valid, False otherwise
    """
    print_header("Validating Package Structure")

    required_files = [
        "lambda_function.py",
        "remediations/__init__.py",
        "remediations/remediation_registry.py",
        "remediations/s3_remediations.py",
        "remediations/iam_remediations.py",
        "remediations/rds_remediations.py",
        "remediations/sg_remediations.py",
    ]

    try:
        with zipfile.ZipFile(package_path, 'r') as zipf:
            file_list = zipf.namelist()

            print_info("Checking required files...")
            all_valid = True

            for required_file in required_files:
                if required_file in file_list:
                    print_success(f"[OK] {required_file}")
                else:
                    print_error(f"[MISSING] {required_file}")
                    all_valid = False

            # Check for unexpected files
            print_info("\nChecking package contents...")
            for file in sorted(file_list):
                size = zipf.getinfo(file).file_size
                print_info(f"  {file} ({size:,} bytes)")

            if all_valid:
                print_success("\n[OK] Package structure is valid")
                return True
            else:
                print_error("\n[ERROR] Package structure validation failed")
                return False

    except Exception as e:
        print_error(f"Error validating package: {e}")
        return False


def main():
    """Main entry point for build script."""
    parser = argparse.ArgumentParser(
        description="Build remediation engine Lambda deployment package"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output path for package zip file"
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload package to S3 after building"
    )
    parser.add_argument(
        "--bucket", "-b",
        help="S3 bucket name for upload"
    )
    parser.add_argument(
        "--key-prefix",
        help="S3 key prefix for upload"
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include test files in package (not recommended)"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate existing package, don't rebuild"
    )

    args = parser.parse_args()

    try:
        # Validate only mode
        if args.validate_only:
            if not args.output:
                print_error("--validate-only requires --output specifying package to validate")
                return 1

            print_header("Validation Only Mode")
            is_valid = validate_package_structure(args.output)
            return 0 if is_valid else 1

        # Build package
        print_header("Remediation Engine Package Builder")
        print_info(f"Timestamp: {datetime.now().isoformat()}")

        package_info = create_deployment_package(
            output_path=args.output,
            include_tests=args.include_tests
        )

        # Validate package
        if not validate_package_structure(package_info["path"]):
            print_error("Package validation failed")
            return 1

        # Upload to S3 if requested
        if args.upload:
            if not args.bucket:
                print_error("--upload requires --bucket")
                return 1

            upload_info = upload_to_s3(
                package_path=package_info["path"],
                bucket_name=args.bucket,
                key_prefix=args.key_prefix
            )

            print_header("Build Summary")
            print_success("[OK] Package built and uploaded successfully!")
            print_info(f"Local: {package_info['path']}")
            print_info(f"S3: {upload_info['s3_uri']}")
            print_info(f"Version: {upload_info['version_id']}")

            # Return S3 info for use in deployment scripts
            print(f"\nS3_KEY={upload_info['key']}")
            print(f"S3_VERSION={upload_info['version_id']}")

        else:
            print_header("Build Summary")
            print_success("[OK] Package built successfully!")
            print_info(f"Local: {package_info['path']}")
            print_info(f"Size: {package_info['size']:,} bytes")

        return 0

    except Exception as e:
        print_error(f"Build failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())