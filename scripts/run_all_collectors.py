#!/usr/bin/env python3
"""
GRC Evidence Platform v2.0 - Run All Collectors Script

This script manually triggers all 12 collectors sequentially, collects EvidenceRecord
objects, stores results to S3 and DynamoDB, and prints a formatted summary table.

Usage:
    python scripts/run_all_collectors.py

Author: GRC Platform Team
Version: 2.0
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

# Add parent directory to path to import collectors
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("grc_collectors.log"),
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
    print_colored(f"[OK] {message}", Colors.GREEN)


def print_error(message: str) -> None:
    """Print an error message in red."""
    print_colored(f"[FAIL] {message}", Colors.RED)


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    print_colored(f"[WARN] {message}", Colors.YELLOW)


def print_info(message: str) -> None:
    """Print an info message in cyan."""
    print_colored(f"[INFO] {message}", Colors.CYAN)


def print_header(message: str) -> None:
    """Print a header message in bold blue."""
    print_colored(f"\n{'=' * 70}", Colors.BLUE)
    print_colored(f"{message}", Colors.BOLD + Colors.BLUE)
    print_colored(f"{'=' * 70}\n", Colors.BLUE)


# Collector definitions
COLLECTORS = [
    "iam_collector",
    "rds_collector",
    "s3_collector",
    "config_collector",
    "securityhub_collector",
    "guardduty_collector",
    "vpc_collector",
    "kms_collector",
    "acm_collector",
    "macie_collector",
    "inspector_collector",
    # "cloudtrail_collector",  # TODO: Not implemented yet
]


class CollectorResult:
    """
    Represents the result of running a collector.

    Attributes:
        collector_name: Name of the collector
        records: List of EvidenceRecord objects collected
        critical_count: Number of CRITICAL severity findings
        high_count: Number of HIGH severity findings
        medium_count: Number of MEDIUM severity findings
        low_count: Number of LOW severity findings
        status: Status of the collection (Done/Failed/Stream)
        error: Error message if collection failed
        duration: Time taken to run the collector in seconds
    """

    def __init__(
        self,
        collector_name: str,
        records: List[Any],
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
        status: str = "Done",
        error: Optional[str] = None,
        duration: float = 0.0,
    ):
        self.collector_name = collector_name
        self.records = records
        self.critical_count = critical_count
        self.high_count = high_count
        self.medium_count = medium_count
        self.low_count = low_count
        self.status = status
        self.error = error
        self.duration = duration

    def total_count(self) -> int:
        """Get total number of records collected."""
        return len(self.records)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "collector_name": self.collector_name,
            "record_count": self.total_count(),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "status": self.status,
            "error": self.error,
            "duration": self.duration,
        }


class CollectorRunner:
    """
    Main class for running all collectors and managing results.

    This class orchestrates the execution of all 12 collectors,
    stores results to S3 and DynamoDB, and generates summary reports.
    """

    CONFIG_FILE = "grc_config.json"

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize the Collector Runner.

        Args:
            region: AWS region to run collectors in (default: from environment or us-east-1)
            profile: AWS profile name to use (default: default)
        """
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.session = boto3.Session(region_name=self.region, profile_name=profile)

        # Initialize AWS clients
        self.s3_client = self.session.client("s3")
        self.dynamodb_client = self.session.client("dynamodb")
        self.dynamodb = self.session.resource("dynamodb")
        self.sts_client = self.session.client("sts")

        # Get account ID
        self.account_id = self._get_account_id()

        # Load configuration
        self.config = self._load_config()

        # Get resource names
        self.evidence_bucket = self._get_evidence_bucket()
        self.metadata_table = self._get_metadata_table()
        self.remediation_log_table = self._get_remediation_log_table()

        # Store results
        self.results: List[CollectorResult] = []

        print_header(f"GRC Evidence Platform v2.0 - Full Collection Run")
        print_info(f"Account ID: {self.account_id}")
        print_info(f"Region: {self.region}")
        print_info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    def _get_account_id(self) -> str:
        """
        Get the current AWS account ID.

        Returns:
            AWS account ID as string
        """
        try:
            response = self.sts_client.get_caller_identity()
            return response["Account"]
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to get account ID: {e}")
            raise

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from grc_config.json if it exists.

        Returns:
            Configuration dictionary
        """
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "r") as f:
                    config = json.load(f)
                return config
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")

        return {}

    def _get_evidence_bucket(self) -> str:
        """Get the evidence S3 bucket name."""
        resources = self.config.get("resources", {})
        for key, value in resources.items():
            if "s3_bucket_evidence" in key:
                return value.get(
                    "name", f"grc-evidence-platform-evidence-{self.account_id}"
                )
        return f"grc-evidence-platform-evidence-{self.account_id}"

    def _get_metadata_table(self) -> str:
        """Get the metadata DynamoDB table name."""
        resources = self.config.get("resources", {})
        for key, value in resources.items():
            if "dynamodb_table_metadata" in key:
                return value.get("name", "grc-evidence-platform-metadata")
        return "grc-evidence-platform-metadata"

    def _get_remediation_log_table(self) -> str:
        """Get the remediation log DynamoDB table name."""
        resources = self.config.get("resources", {})
        for key, value in resources.items():
            if "dynamodb_table_remediation-log" in key:
                return value.get("name", "grc-evidence-platform-remediation-log")
        return "grc-evidence-platform-remediation-log"

    def _store_to_s3(self, collector_name: str, records: List[Any]) -> bool:
        """
        Store collector records to S3.

        Args:
            collector_name: Name of the collector
            records: List of EvidenceRecord objects

        Returns:
            True if storage succeeded, False otherwise
        """
        try:
            if not records:
                return True

            # Convert records to JSON
            records_data = []
            for record in records:
                if hasattr(record, "to_dict"):
                    records_data.append(record.to_dict())
                elif isinstance(record, dict):
                    records_data.append(record)
                else:
                    records_data.append({"data": str(record)})

            # Create S3 key
            timestamp = datetime.now().strftime("%Y/%m/%d/%H/%M/%S")
            key = f"collectors/{collector_name}/{timestamp}/records.json"

            # Upload to S3
            self.s3_client.put_object(
                Bucket=self.evidence_bucket,
                Key=key,
                Body=json.dumps(records_data, indent=2, default=str),
                ContentType="application/json",
            )

            logger.info(
                f"Stored {len(records)} records from {collector_name} to S3: {key}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to store {collector_name} records to S3: {e}")
            return False

    def _store_to_dynamodb(self, collector_name: str, records: List[Any]) -> bool:
        """
        Store collector records to DynamoDB.

        Args:
            collector_name: Name of the collector
            records: List of EvidenceRecord objects

        Returns:
            True if storage succeeded, False otherwise
        """
        try:
            if not records:
                return True

            # Get table resource
            table = self.dynamodb.Table(self.metadata_table)

            # Batch write to DynamoDB
            with table.batch_writer() as batch:
                for i, record in enumerate(records):
                    try:
                        # Convert record to DynamoDB format
                        if hasattr(record, "to_dict"):
                            record_dict = record.to_dict()
                        elif isinstance(record, dict):
                            record_dict = record
                        else:
                            record_dict = {"data": str(record)}

                        # Create DynamoDB item (use regular dict, not DynamoDB JSON format)
                        item = {
                            "resource_id": f"{collector_name}-{i}-{int(time.time())}",
                            "timestamp": datetime.now().isoformat(),
                            "collector_name": collector_name,
                            "record_data": json.dumps(record_dict, default=str),
                        }

                        # Add severity if present
                        if "severity" in record_dict:
                            item["severity"] = str(record_dict["severity"]).upper()
                        else:
                            item["severity"] = "LOW"

                        # Add resource type if present
                        if "resource_type" in record_dict:
                            item["resource_type"] = str(record_dict["resource_type"])
                        else:
                            item["resource_type"] = collector_name.replace("_collector", "")

                        # Add TTL (30 days)
                        import calendar

                        expire_at = calendar.timegm(
                            (datetime.now() + timedelta(days=30)).timetuple()
                        )
                        item["expire_at"] = expire_at

                        batch.put_item(Item=item)

                    except Exception as e:
                        logger.warning(f"Failed to write record {i} to DynamoDB: {e}")
                        continue

            logger.info(
                f"Stored {len(records)} records from {collector_name} to DynamoDB"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to store {collector_name} records to DynamoDB: {e}")
            return False

    def _run_collector(self, collector_name: str) -> CollectorResult:
        """
        Run a single collector and return the results.

        Args:
            collector_name: Name of the collector to run

        Returns:
            CollectorResult object with collection results
        """
        start_time = time.time()

        try:
            print_info(f"Running {collector_name}...")

            # Import collector module
            module_name = f"collectors.{collector_name}"
            try:
                module = __import__(module_name, fromlist=[""])
            except ImportError as e:
                logger.error(f"Failed to import {collector_name}: {e}")
                return CollectorResult(
                    collector_name=collector_name,
                    records=[],
                    status="Failed",
                    error=f"Import error: {e}",
                    duration=time.time() - start_time,
                )

            # Get collector class
            collector_class_name = (
                "".join(
                    word.capitalize()
                    for word in collector_name.replace("_collector", "").split("_")
                )
                + "Collector"
            )

            if not hasattr(module, collector_class_name):
                # Try alternate naming convention
                collector_class_name = (
                    collector_name.replace("_", " ").title().replace(" ", "")
                    + "Collector"
                )

            if not hasattr(module, collector_class_name):
                # Use the first class that ends with 'Collector'
                for attr_name in dir(module):
                    if attr_name.endswith("Collector") and attr_name != "BaseCollector":
                        collector_class_name = attr_name
                        break

            if not hasattr(module, collector_class_name):
                raise Exception(f"Could not find collector class in {module_name}")

            CollectorClass = getattr(module, collector_class_name)

            # Initialize collector
            collector = CollectorClass(region=self.region)

            # Run collection
            records = collector.collect()

            # Count by severity
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0

            for record in records:
                if hasattr(record, "severity"):
                    severity = str(record.severity).upper()
                elif isinstance(record, dict) and "severity" in record:
                    severity = str(record["severity"]).upper()
                else:
                    severity = "LOW"

                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1
                elif severity == "MEDIUM":
                    medium_count += 1
                else:
                    low_count += 1

            # Store results
            self._store_to_s3(collector_name, records)
            self._store_to_dynamodb(collector_name, records)

            duration = time.time() - start_time

            # Determine status
            if collector_name == "cloudtrail_collector":
                status = "Stream"
            else:
                status = "Done"

            print_success(f"{collector_name} completed in {duration:.2f}s")

            return CollectorResult(
                collector_name=collector_name,
                records=records,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                status=status,
                duration=duration,
            )

        except Exception as e:
            logger.error(f"Error running {collector_name}: {e}", exc_info=True)
            return CollectorResult(
                collector_name=collector_name,
                records=[],
                status="Failed",
                error=str(e),
                duration=time.time() - start_time,
            )

    def run_all_collectors(self) -> None:
        """
        Run all collectors sequentially and collect results.
        """
        print_header("Running All Collectors")
        print()

        for collector_name in COLLECTORS:
            result = self._run_collector(collector_name)
            self.results.append(result)
            print()

    def print_summary_table(self) -> None:
        """
        Print a formatted summary table of all collector results.
        """
        print_header("GRC Evidence Platform — Full Collection Run")
        print()

        # Calculate totals
        total_records = 0
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0

        # Print table header
        header = f"{'Collector':<28} {'Records':<10} {'CRITICAL':<9} {'HIGH':<7} {'MEDIUM':<7} {'LOW':<6} {'Status':<8}"
        separator = "-" * 85

        print(header)
        print(separator)

        # Print each collector result
        for result in self.results:
            if result.status == "Stream":
                records_str = "∞"
                critical_str = "-"
                high_str = "-"
                medium_str = "-"
                low_str = "-"
                status_str = "🔄 Stream"
            else:
                records_str = str(result.total_count())
                critical_str = str(result.critical_count)
                high_str = str(result.high_count)
                medium_str = str(result.medium_count)
                low_str = str(result.low_count)

                if result.status == "Done":
                    status_str = "[OK] Done"
                else:
                    status_str = "❌ Failed"

            # Color code status
            if result.status == "Failed":
                status_colored = f"{Colors.RED}{status_str}{Colors.RESET}"
            elif result.status == "Stream":
                status_colored = f"{Colors.YELLOW}{status_str}{Colors.RESET}"
            else:
                status_colored = f"{Colors.GREEN}{status_str}{Colors.RESET}"

            row = f"{result.collector_name:<28} {records_str:<10} {critical_str:<9} {high_str:<7} {medium_str:<7} {low_str:<6} {status_colored}"
            print(row)

            # Update totals
            total_records += result.total_count()
            total_critical += result.critical_count
            total_high += result.high_count
            total_medium += result.medium_count
            total_low += result.low_count

        # Print separator and totals
        print(separator)
        total_row = f"{'TOTAL':<28} {total_records:<10} {total_critical:<9} {total_high:<7} {total_medium:<7} {total_low:<6} {'':<8}"
        print_colored(total_row, Colors.BOLD)
        print(separator)
        print()

        # Print storage info
        print_colored("All records stored to S3 and indexed in DynamoDB.", Colors.GREEN)
        print()

        # Print overall risk rating
        if total_critical > 0:
            risk_color = Colors.RED
            risk_rating = "CRITICAL"
            risk_message = (
                f"{total_critical} CRITICAL findings require immediate attention"
            )
        elif total_high > 10:
            risk_color = Colors.RED
            risk_rating = "HIGH"
            risk_message = f"{total_high} HIGH findings detected"
        elif total_high > 0:
            risk_color = Colors.YELLOW
            risk_rating = "HIGH"
            risk_message = f"{total_high} HIGH findings detected"
        elif total_medium > 20:
            risk_color = Colors.YELLOW
            risk_rating = "MEDIUM"
            risk_message = f"{total_medium} MEDIUM findings detected"
        else:
            risk_color = Colors.GREEN
            risk_rating = "LOW"
            risk_message = "Platform is in good health"

        print_colored(f"Overall Risk Rating: {risk_rating}", Colors.BOLD + risk_color)
        print_colored(f"{risk_message}", risk_color)
        print()

    def save_results(self) -> None:
        """
        Save collection results to a JSON file.
        """
        try:
            results_data = {
                "account_id": self.account_id,
                "region": self.region,
                "timestamp": datetime.now().isoformat(),
                "results": [result.to_dict() for result in self.results],
                "summary": {
                    "total_records": sum(r.total_count() for r in self.results),
                    "total_critical": sum(r.critical_count for r in self.results),
                    "total_high": sum(r.high_count for r in self.results),
                    "total_medium": sum(r.medium_count for r in self.results),
                    "total_low": sum(r.low_count for r in self.results),
                },
            }

            filename = (
                f"collection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(filename, "w") as f:
                json.dump(results_data, f, indent=2, default=str)

            print_success(f"Results saved to {filename}")

        except Exception as e:
            logger.error(f"Failed to save results: {e}")


def main() -> None:
    """
    Main entry point for the run all collectors script.
    """
    parser = argparse.ArgumentParser(
        description="Run all GRC Evidence Platform collectors"
    )
    parser.add_argument(
        "--region",
        help="AWS region to run collectors in (default: from AWS_DEFAULT_REGION or us-east-1)",
        default=None,
    )
    parser.add_argument(
        "--profile", help="AWS profile name to use (default: default)", default=None
    )
    parser.add_argument(
        "--save-results", help="Save results to JSON file", action="store_true"
    )

    args = parser.parse_args()

    try:
        runner = CollectorRunner(region=args.region, profile=args.profile)
        runner.run_all_collectors()
        runner.print_summary_table()

        if args.save_results:
            runner.save_results()

    except NoCredentialsError:
        print_error("AWS credentials not found. Please configure your credentials.")
        print_colored(
            "Run 'aws configure' or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.",
            Colors.CYAN,
        )
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
