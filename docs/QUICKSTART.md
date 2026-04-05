# Quick Start Guide

This guide will help you deploy the Version 1 (Python/Boto3) of the AWS GRC Evidence Collector in 3 simple steps.

## Step 1: Configure AWS Credentials

Ensure you have the AWS CLI installed and configured with Administrator access.

```bash
aws configure
```
Provide your Access Key, Secret Key, and set the default region to `us-east-1`.

## Step 2: Deploy the Infrastructure

Run the setup script. This script uses `boto3` to create all necessary AWS resources (S3, DynamoDB, SNS, IAM, Lambda, EventBridge, CloudTrail) in the correct dependency order.

```bash
pip install boto3
python setup.py
```

Wait for the script to complete. It will print a summary of the created resources and save their ARNs to `grc_config.json`.

## Step 3: Test the System

Run the test script to simulate AWS API events and verify that the Evidence Collector processes them correctly.

```bash
python test_events.py
```

You should see output indicating that HIGH, MEDIUM, and LOW priority events were successfully processed, stored in S3, indexed in DynamoDB, and alerted via SNS (for HIGH priority).

## Cleanup

When you are finished, run the teardown script to remove all resources and avoid any potential charges.

```bash
python teardown.py
```
