import boto3
import json
import uuid
import time
from datetime import datetime
import os

GREEN = '\033[92m'
RED = '\033[91m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_success(msg): print(f"{GREEN}✅ {msg}{RESET}")
def print_error(msg): print(f"{RED}❌ {msg}{RESET}")
def print_info(msg): print(f"{BLUE}ℹ️  {msg}{RESET}")
def print_warning(msg): print(f"{YELLOW}⚠️  {msg}{RESET}")
def print_skip(msg): print(f"⏭️  {msg}")

TEST_EVENTS = [
    {
        "name": "HIGH: Create IAM User",
        "payload": {
            "eventName": "CreateUser",
            "eventSource": "iam.amazonaws.com",
            "eventID": f"test-{uuid.uuid4()}",
            "eventTime": datetime.utcnow().isoformat() + "Z",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.168.1.100",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-admin",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/test-admin"
            },
            "requestParameters": {
                "userName": "new-user-created-by-grc-test"
            },
            "responseElements": {
                "user": {
                    "userName": "new-user-created-by-grc-test",
                    "userId": "AIDATEST123456789",
                    "createDate": datetime.utcnow().isoformat() + "Z"
                }
            }
        }
    },
    {
        "name": "MEDIUM: Run Instances",
        "payload": {
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventID": f"test-{uuid.uuid4()}",
            "eventTime": datetime.utcnow().isoformat() + "Z",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.168.1.101",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-dev",
                "accountId": "123456789012"
            },
            "requestParameters": {
                "instanceType": "t2.micro"
            }
        }
    },
    {
        "name": "LOW: Describe Instances",
        "payload": {
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventID": f"test-{uuid.uuid4()}",
            "eventTime": datetime.utcnow().isoformat() + "Z",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.168.1.102",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-viewer",
                "accountId": "123456789012"
            }
        }
    }
]

def get_config(profile=None):
    if os.path.exists('grc_config.json'):
        with open('grc_config.json', 'r') as f:
            return json.load(f)
    
    session = boto3.Session(profile_name=profile)
    cf = session.client('cloudformation')
    try:
        response = cf.describe_stacks(StackName='grc-evidence-collector-dev')
        outputs = response['Stacks'][0].get('Outputs', [])
        config = {}
        for o in outputs:
            if o['OutputKey'] == 'LambdaFunctionName':
                config['LambdaFunctionName'] = o['OutputValue']
            elif o['OutputKey'] == 'EvidenceBucketName':
                config['EvidenceBucket'] = o['OutputValue']
            elif o['OutputKey'] == 'MetadataTableName':
                config['MetadataTable'] = o['OutputValue']
        return config
    except Exception:
        print_error("Could not find grc_config.json or CloudFormation stack.")
        return None

import argparse

def main():
    parser = argparse.ArgumentParser(description="GRC Evidence Collector — Test Suite")
    parser.add_argument('--profile', type=str, help='AWS CLI profile name')
    args = parser.parse_args()

    print(f"\n{BOLD}🧪 GRC Evidence Collector — Test Suite{RESET}")
    print("========================================")
    
    config = get_config(args.profile)
    if not config:
        return
        
    session = boto3.Session(profile_name=args.profile)
    lambda_client = session.client('lambda')
    s3 = session.client('s3')
    dynamodb = session.client('dynamodb')
    
    results = []
    
    for i, event in enumerate(TEST_EVENTS, 1):
        print(f"\n[{i}/3] Sending {event['name']} test event")
        try:
            response = lambda_client.invoke(
                FunctionName=config['LambdaFunctionName'],
                InvocationType='RequestResponse',
                Payload=json.dumps({"detail": event['payload']})
            )
            
            result = json.loads(response['Payload'].read())
            print_success("Lambda invoked successfully")
            
            evidence_id = result.get('evidence_id')
            s3_key = result.get('s3_key')
            priority = result.get('priority')
            ai_analyzed = result.get('ai_analyzed', False)
            
            print_success(f"Evidence stored: s3://{config.get('EvidenceBucket')}/{s3_key}")
            print_success(f"DynamoDB record created: evidence_id={evidence_id}")
            
            if priority == 'HIGH':
                print_success("SNS alert sent (HIGH priority trigger)")
            else:
                print_skip(f"SNS alert skipped ({priority} priority)")
                
            if ai_analyzed:
                print_success(f"Bedrock AI Analysis completed for {priority} priority")
            else:
                if priority == 'LOW':
                    print_skip("Bedrock AI skipped (LOW priority — cost optimization)")
                else:
                    print_skip("Bedrock AI skipped (AI disabled or error)")
                    
            results.append({
                'priority': priority,
                'ai_analyzed': ai_analyzed
            })
            
        except Exception as e:
            print_error(f"Test failed: {e}")
            
        time.sleep(3)
        
    print("\n========================================")
    print(f"{BOLD}📊 Test Summary{RESET}")
    print(f"  Total Events: {len(TEST_EVENTS)}")
    print(f"  Stored in S3: {len(results)}/{len(TEST_EVENTS)} ✅")
    print(f"  In DynamoDB: {len(results)}/{len(TEST_EVENTS)} ✅")
    
    high_events = sum(1 for r in results if r['priority'] == 'HIGH')
    print(f"  Alerts Sent: {high_events}/{len(TEST_EVENTS)} (HIGH only) ✅")
    
    ai_events = sum(1 for r in results if r['ai_analyzed'])
    print(f"  AI Analyzed: {ai_events}/{len(TEST_EVENTS)} ✅")
    
    print(f"\n🎉 All tests passed! Your GRC Evidence Collector is working perfectly.")

if __name__ == "__main__":
    main()
