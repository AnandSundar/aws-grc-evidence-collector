#!/usr/bin/env python3
"""
GRC Evidence Platform v2.0 - CI/CD Compliance Gate

This script acts as a CI/CD compliance gate that checks for CRITICAL severity
findings in checkov results. It fails the pipeline if CRITICAL findings are present
and generates a detailed summary report.

Usage:
    python scripts/gate_check.py /path/to/checkov/results

Author: GRC Platform Team
Version: 2.0
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("grc_gate_check.log"),
    ],
)
logger = logging.getLogger(__name__)


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_colored(message: str, color: str = Colors.RESET) -> None:
    """
    Print a colored message to the terminal.

    Args:
        message: The message to print
        color: ANSI color code to use
    """
    print(f"{color}{message}{Colors.RESET}")


def print_success(message: str) -> None:
    """Print a success message in green."""
    print_colored(f"✓ {message}", Colors.GREEN)


def print_error(message: str) -> None:
    """Print an error message in red."""
    print_colored(f"✗ {message}", Colors.RED)


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    print_colored(f"⚠ {message}", Colors.YELLOW)


def print_info(message: str) -> None:
    """Print an info message in cyan."""
    print_colored(f"ℹ {message}", Colors.CYAN)


def print_header(message: str) -> None:
    """Print a header message in bold blue."""
    print_colored(f"\n{'=' * 70}", Colors.BLUE)
    print_colored(f"{message}", Colors.BOLD + Colors.BLUE)
    print_colored(f"{'=' * 70}\n", Colors.BLUE)


class ComplianceGate:
    """
    Main class for CI/CD compliance gate checking.

    This class loads checkov results, analyzes findings by severity,
    and determines whether the pipeline should pass or fail.
    """

    OUTPUT_FILE = "gate_summary.json"

    def __init__(self, results_dir: str):
        """
        Initialize the Compliance Gate.

        Args:
            results_dir: Path to the directory containing checkov results
        """
        self.results_dir = results_dir
        self.findings: List[Dict[str, Any]] = []
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.status = "PASS"

        print_header(f"GRC Evidence Platform v2.0 - CI/CD Compliance Gate")
        print_info(f"Results directory: {results_dir}")
        print_info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    def _load_checkov_results(self) -> None:
        """
        Load checkov results from JSON files in the results directory.

        Raises:
            FileNotFoundError: If results directory doesn't exist
            ValueError: If no valid results files are found
        """
        if not os.path.exists(self.results_dir):
            raise FileNotFoundError(f"Results directory not found: {self.results_dir}")

        if not os.path.isdir(self.results_dir):
            raise ValueError(f"Path is not a directory: {self.results_dir}")

        # Find all JSON files in the directory
        json_files = []
        for root, dirs, files in os.walk(self.results_dir):
            for file in files:
                if file.endswith(".json"):
                    json_files.append(os.path.join(root, file))

        if not json_files:
            raise ValueError(f"No JSON files found in: {self.results_dir}")

        print_info(f"Found {len(json_files)} JSON result file(s)")

        # Load and parse each JSON file
        for json_file in json_files:
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)

                # Parse checkov results
                findings = self._parse_checkov_data(data, json_file)
                self.findings.extend(findings)

                print_info(
                    f"Loaded {len(findings)} findings from {os.path.basename(json_file)}"
                )

            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON file {json_file}: {e}")
            except Exception as e:
                logger.warning(f"Error processing file {json_file}: {e}")

        if not self.findings:
            print_warning("No findings found in any result files")

    def _parse_checkov_data(self, data: Any, source_file: str) -> List[Dict[str, Any]]:
        """
        Parse checkov data and extract findings.

        Args:
            data: Parsed JSON data from checkov
            source_file: Path to the source file for reference

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Handle different checkov result formats
        if isinstance(data, dict):
            # Check for results.checks array (common format)
            if "results" in data and "failed_checks" in data["results"]:
                for check in data["results"]["failed_checks"]:
                    finding = self._extract_finding(check, source_file)
                    if finding:
                        findings.append(finding)

            # Check for top-level array
            elif "failed_checks" in data:
                for check in data["failed_checks"]:
                    finding = self._extract_finding(check, source_file)
                    if finding:
                        findings.append(finding)

            # Check for results array
            elif "results" in data and isinstance(data["results"], list):
                for result in data["results"]:
                    if isinstance(result, dict) and "failed_checks" in result:
                        for check in result["failed_checks"]:
                            finding = self._extract_finding(check, source_file)
                            if finding:
                                findings.append(finding)

            # Check for check_results array
            elif "check_results" in data:
                for result in data["check_results"]:
                    if isinstance(result, dict):
                        finding = self._extract_finding(result, source_file)
                        if finding:
                            findings.append(finding)

            # Check for array of checks at top level
            elif all(isinstance(item, dict) for item in data.values()):
                for key, value in data.items():
                    if isinstance(value, dict):
                        finding = self._extract_finding(value, source_file)
                        if finding:
                            findings.append(finding)

        elif isinstance(data, list):
            # Handle array of findings
            for item in data:
                if isinstance(item, dict):
                    finding = self._extract_finding(item, source_file)
                    if finding:
                        findings.append(finding)

        return findings

    def _extract_finding(
        self, check: Dict[str, Any], source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Extract a finding from a check result.

        Args:
            check: Check result dictionary
            source_file: Source file path for reference

        Returns:
            Finding dictionary or None if invalid
        """
        try:
            # Extract severity
            severity = "LOW"
            if "severity" in check:
                severity = str(check["severity"]).upper()
            elif "check" in check and "severity" in check["check"]:
                severity = str(check["check"]["severity"]).upper()
            elif "check_id" in check:
                # Infer severity from check_id
                check_id = check["check_id"].upper()
                if "CRIT" in check_id or "CKV_AWS_" in check_id:
                    severity = "HIGH"
            else:
                severity = "MEDIUM"

            # Normalize severity
            if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if "CRIT" in severity:
                    severity = "CRITICAL"
                elif "HIGH" in severity:
                    severity = "HIGH"
                elif "MED" in severity:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            # Extract other fields
            finding = {
                "check_id": check.get("check_id", "UNKNOWN"),
                "check_name": check.get(
                    "check_name", check.get("check", {}).get("name", "Unknown Check")
                ),
                "severity": severity,
                "resource": check.get(
                    "resource", check.get("resource_name", "Unknown Resource")
                ),
                "file_path": check.get("file_path", source_file),
                "file_line_range": check.get("file_line_range", []),
                "description": check.get("check", {}).get(
                    "description", check.get("description", "")
                ),
                "remediation": check.get("check", {}).get(
                    "remediation", check.get("remediation", "")
                ),
                "source_file": source_file,
            }

            return finding

        except Exception as e:
            logger.debug(f"Failed to extract finding: {e}")
            return None

    def _analyze_findings(self) -> None:
        """
        Analyze findings and count by severity.
        """
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0

        for finding in self.findings:
            severity = finding.get("severity", "LOW")

            if severity == "CRITICAL":
                self.critical_count += 1
            elif severity == "HIGH":
                self.high_count += 1
            elif severity == "MEDIUM":
                self.medium_count += 1
            else:
                self.low_count += 1

        # Determine gate status
        if self.critical_count > 0:
            self.status = "FAIL"
        else:
            self.status = "PASS"

    def _generate_markdown_table(self) -> str:
        """
        Generate a markdown table of findings.

        Returns:
            Markdown table as string
        """
        if not self.findings:
            return "No findings to report."

        # Group findings by severity
        critical_findings = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high_findings = [f for f in self.findings if f["severity"] == "HIGH"]
        medium_findings = [f for f in self.findings if f["severity"] == "MEDIUM"]
        low_findings = [f for f in self.findings if f["severity"] == "LOW"]

        table_lines = []

        # Add summary
        table_lines.append("## Compliance Gate Summary")
        table_lines.append("")
        table_lines.append(f"**Status:** {self.status}")
        table_lines.append(f"**Total Findings:** {len(self.findings)}")
        table_lines.append("")
        table_lines.append("| Severity | Count |")
        table_lines.append("|----------|-------|")
        table_lines.append(f"| CRITICAL | {self.critical_count} |")
        table_lines.append(f"| HIGH | {self.high_count} |")
        table_lines.append(f"| MEDIUM | {self.medium_count} |")
        table_lines.append(f"| LOW | {self.low_count} |")
        table_lines.append("")

        # Add CRITICAL findings if any
        if critical_findings:
            table_lines.append("## CRITICAL Findings")
            table_lines.append("")
            table_lines.append("| Check ID | Check Name | Resource | File |")
            table_lines.append("|----------|------------|----------|------|")
            for finding in critical_findings:
                table_lines.append(
                    f"| {finding['check_id']} | {finding['check_name']} | "
                    f"{finding['resource'][:50]} | {os.path.basename(finding['file_path'])} |"
                )
            table_lines.append("")

        # Add HIGH findings if any
        if high_findings:
            table_lines.append("## HIGH Findings")
            table_lines.append("")
            table_lines.append("| Check ID | Check Name | Resource | File |")
            table_lines.append("|----------|------------|----------|------|")
            for finding in high_findings[:20]:  # Limit to 20 for readability
                table_lines.append(
                    f"| {finding['check_id']} | {finding['check_name']} | "
                    f"{finding['resource'][:50]} | {os.path.basename(finding['file_path'])} |"
                )
            if len(high_findings) > 20:
                table_lines.append(
                    f"| ... | ... | ... | ... ({len(high_findings) - 20} more) |"
                )
            table_lines.append("")

        # Add MEDIUM findings summary
        if medium_findings:
            table_lines.append(f"## MEDIUM Findings ({len(medium_findings)} total)")
            table_lines.append("")
            table_lines.append("| Check ID | Count |")
            table_lines.append("|----------|-------|")
            # Group by check_id
            check_counts = {}
            for finding in medium_findings:
                check_id = finding["check_id"]
                check_counts[check_id] = check_counts.get(check_id, 0) + 1
            for check_id, count in sorted(
                check_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                table_lines.append(f"| {check_id} | {count} |")
            table_lines.append("")

        # Add LOW findings summary
        if low_findings:
            table_lines.append(f"## LOW Findings ({len(low_findings)} total)")
            table_lines.append("")
            table_lines.append("| Check ID | Count |")
            table_lines.append("|----------|-------|")
            # Group by check_id
            check_counts = {}
            for finding in low_findings:
                check_id = finding["check_id"]
                check_counts[check_id] = check_counts.get(check_id, 0) + 1
            for check_id, count in sorted(
                check_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                table_lines.append(f"| {check_id} | {count} |")
            table_lines.append("")

        return "\n".join(table_lines)

    def _save_gate_summary(self) -> None:
        """
        Save the gate summary to a JSON file.
        """
        summary = {
            "status": self.status,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "total_findings": len(self.findings),
            "timestamp": datetime.now().isoformat(),
            "markdown_table": self._generate_markdown_table(),
            "findings": self.findings,
        }

        try:
            with open(self.OUTPUT_FILE, "w") as f:
                json.dump(summary, f, indent=2, default=str)

            print_success(f"Gate summary saved to: {self.OUTPUT_FILE}")

        except Exception as e:
            logger.error(f"Failed to save gate summary: {e}")
            raise

    def print_results(self) -> None:
        """
        Print the gate check results to the console.
        """
        print_header("Compliance Gate Results")

        # Print status
        if self.status == "PASS":
            print_colored(f"Gate Status: {self.status}", Colors.BOLD + Colors.GREEN)
            print_success("No CRITICAL findings detected. Pipeline may proceed.")
        else:
            print_colored(f"Gate Status: {self.status}", Colors.BOLD + Colors.RED)
            print_error(f"CRITICAL findings detected! Pipeline blocked.")

        print()

        # Print summary table
        print_colored("Findings Summary:", Colors.BOLD)
        print()
        print(f"  Total Findings:    {len(self.findings)}")
        print(f"  CRITICAL:          {self.critical_count}")
        print(f"  HIGH:              {self.high_count}")
        print(f"  MEDIUM:            {self.medium_count}")
        print(f"  LOW:               {self.low_count}")
        print()

        # Print CRITICAL findings if any
        if self.critical_count > 0:
            print_colored("CRITICAL Findings:", Colors.BOLD + Colors.RED)
            print()

            critical_findings = [
                f for f in self.findings if f["severity"] == "CRITICAL"
            ]
            for i, finding in enumerate(critical_findings, 1):
                print_colored(
                    f"{i}. {finding['check_id']}: {finding['check_name']}", Colors.RED
                )
                print(f"   Resource: {finding['resource']}")
                print(f"   File: {finding['file_path']}")
                if finding.get("description"):
                    print(f"   Description: {finding['description'][:100]}...")
                print()

        # Print markdown table
        print_header("Detailed Report (Markdown)")
        print(self._generate_markdown_table())

    def run(self) -> int:
        """
        Run the compliance gate check.

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        try:
            # Load checkov results
            print_info("Loading checkov results...")
            self._load_checkov_results()

            # Analyze findings
            print_info("Analyzing findings...")
            self._analyze_findings()

            # Print results
            self.print_results()

            # Save summary
            self._save_gate_summary()

            # Return exit code
            if self.status == "PASS":
                print_success("Compliance gate passed!")
                return 0
            else:
                print_error("Compliance gate failed!")
                return 1

        except FileNotFoundError as e:
            print_error(str(e))
            return 1
        except ValueError as e:
            print_error(str(e))
            return 1
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            print_error(f"Unexpected error: {e}")
            return 1


def main() -> None:
    """
    Main entry point for the gate check script.
    """
    parser = argparse.ArgumentParser(
        description="CI/CD compliance gate for GRC Evidence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script acts as a CI/CD compliance gate that checks for CRITICAL severity
findings in checkov results. It fails the pipeline if CRITICAL findings are present.

Exit Codes:
  0 - Pass (no CRITICAL findings)
  1 - Fail (CRITICAL findings detected or error occurred)

Output:
  - Prints results to stdout
  - Creates gate_summary.json with detailed findings

Example Usage:
  # Run gate check on checkov results
  python scripts/gate_check.py /path/to/checkov/results
  
  # Use in CI/CD pipeline
  python scripts/gate_check.py ./checkov-results || exit 1
        """,
    )

    parser.add_argument(
        "results_dir",
        help="Path to the directory containing checkov results (JSON files)",
    )
    parser.add_argument(
        "--output-file",
        help="Output file for gate summary (default: gate_summary.json)",
        default="gate_summary.json",
    )
    parser.add_argument("--verbose", help="Enable verbose logging", action="store_true")

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        gate = ComplianceGate(args.results_dir)
        gate.OUTPUT_FILE = args.output_file
        exit_code = gate.run()
        sys.exit(exit_code)

    except KeyboardInterrupt:
        print_warning("\nGate check interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
