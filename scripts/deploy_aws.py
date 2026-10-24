"""Deploy (or update) the detector on AWS. Credentials come from env vars / AWS profile, never this file.

Usage:  python scripts/deploy_aws.py            first-time deploy
        python scripts/deploy_aws.py update     push new code to the existing function
Change REGION/P below to suit your account.
"""
import io
import json
import sys
import time
import zipfile
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent.parent
REGION = "ap-south-1"
P = "ananya_"  # prefix for every resource
ROLE = P + "threat_lambda_role"
FUNC = P + "cloudtrail_threat_detector"
RULE = P + "threat_detection_rule"
PATTERN = {
    "detail-type": ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"],
    "$or": [
        {"source": ["aws.signin", "aws.iam", "aws.cloudtrail"]},
        {"detail": {"errorCode": [{"exists": True}]}},
    ],
}


def package():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(ROOT / "src" / "lambda_function.py", "lambda_function.py")
    return buf.getvalue()


def deploy():
    iam = boto3.client("iam", region_name=REGION)
    lam = boto3.client("lambda", region_name=REGION)
    logs = boto3.client("logs", region_name=REGION)
    events = boto3.client("events", region_name=REGION)

    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.attach_role_policy(RoleName=ROLE, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    print("role created:", role_arn)
    time.sleep(12)  # IAM role propagation

    fn_arn = lam.create_function(FunctionName=FUNC, Runtime="python3.12", Role=role_arn,
                                 Handler="lambda_function.lambda_handler", Timeout=10,
                                 Code={"ZipFile": package()})["FunctionArn"]
    print("lambda created:", fn_arn)

    group = "/aws/lambda/" + FUNC
    logs.create_log_group(logGroupName=group)
    logs.put_retention_policy(logGroupName=group, retentionInDays=7)

    rule_arn = events.put_rule(Name=RULE, EventPattern=json.dumps(PATTERN), State="ENABLED")["RuleArn"]
    lam.add_permission(FunctionName=FUNC, StatementId=P + "eventbridge", Action="lambda:InvokeFunction",
                       Principal="events.amazonaws.com", SourceArn=rule_arn)
    events.put_targets(Rule=RULE, Targets=[{"Id": "1", "Arn": fn_arn}])
    print("rule created:", rule_arn)


def update():
    boto3.client("lambda", region_name=REGION).update_function_code(FunctionName=FUNC, ZipFile=package())
    print("function code updated")


if __name__ == "__main__":
    try:
        update() if sys.argv[1:] == ["update"] else deploy()
    except Exception as e:
        print("FAILED:", e)
        sys.exit(1)
