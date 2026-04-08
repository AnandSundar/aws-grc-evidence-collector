#!/usr/bin/env python3
"""
Scorecard Generator Lambda Package Builder

Builds deployment packages for the scorecard generator Lambda function.

Usage:
    python scripts/build_scorecard_package.py

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
    print_colored(f"{'=' * 70}\n", Colors.BLUE + Colors.CYAN)


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def create_deployment_package(
    output_path: str = None
) -> dict:
    """Create Lambda deployment package for scorecard generator.

    Args:
        output_path: Path for output zip file. If None, uses default.

    Returns:
        Dictionary with package info: path, size, file_count, etc.
    """
    project_root = get_project_root()
    scorecard_dir = project_root / "lambda" / "scorecard_generator"

    # Default output path
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = str(project_root / "build" / f"scorecard-generator-{timestamp}.zip")

    # Create output directory if needed
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print_header("Creating Scorecard Generator Lambda Package")
    print_info(f"Project root: {project_root}")
    print_info(f"Source directory: {scorecard_dir}")
    print_info(f"Output path: {output_path}")

    # Verify source directory exists
    if not scorecard_dir.exists():
        print_error(f"Source directory not found: {scorecard_dir}")
        return None

    # Check for handler.py
    handler_file = scorecard_dir / "handler.py"
    if not handler_file.exists():
        print_error(f"Handler file not found: {handler_file}")
        return None

    print_info(f"Handler file: {handler_file}")

    # Create the deployment package
    file_count = 0
    total_size = 0

    try:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add handler.py as lambda_function.py (Lambda expects this)
            lambda_handler_content = handler_file.read_text()
            zipf.writestr("lambda_function.py", lambda_handler_content)
            file_count += 1
            total_size += len(lambda_handler_content)
            print_success(f"Added: lambda_function.py (from handler.py)")

            # Calculate original file size
            original_size = len(lambda_handler_content)

        # Get final package size
        package_size = os.path.getsize(output_path)
        compression_ratio = (1 - package_size / original_size) * 100 if original_size > 0 else 0

        print_header("Package Created Successfully")
        print_success(f"Package created: {output_path}")
        print_info(f"Files included: {file_count}")
        print_info(f"Original size: {format_size(original_size)}")
        print_info(f"Package size: {format_size(package_size)}")
        print_info(f"Compression: {compression_ratio:.1f}%")

        return {
            "path": output_path,
            "size": package_size,
            "file_count": file_count,
            "original_size": original_size,
            "compression_ratio": compression_ratio
        }

    except Exception as e:
        print_error(f"Failed to create package: {e}")
        return None


def format_size(size_bytes: int) -> str:
    """Format byte size as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Build deployment package for Scorecard Generator Lambda"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output path for the zip file",
        default=None
    )

    args = parser.parse_args()

    # Create package
    result = create_deployment_package(output_path=args.output)

    if result:
        print_success(f"\nPackage created: {result['path']}")
        return 0
    else:
        print_error("\nFailed to create package")
        return 1


if __name__ == "__main__":
    sys.exit(main())
