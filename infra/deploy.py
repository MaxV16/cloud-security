#!/usr/bin/env python3
"""
Deploys the serverless honeytoken test bed described in the CA1 report.

Run order:
    python infra/deploy.py guardrails
    python infra/deploy.py deception
    python infra/deploy.py detection
    python infra/deploy.py response

Every step is idempotent, so re-running a step repairs drift instead of
failing.  The canary access key is written to .canary/credentials so the
attack simulation script can pick it up.
"""

import json
import os
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "eu-west-1"
ACCOUNT = boto3.client("sts").get_caller_identity()["Account"]

ROOT = Path(__file__).resolve().parent.parent
CANARY_DIR = ROOT / ".canary"

LOG_BUCKET = f"honeytoken-cloudtrail-{ACCOUNT}"
HONEY_BUCKET = f"prod-backup-credentials-2026-{ACCOUNT}"
TRAIL = "honeytoken-trail"
LOG_GROUP = "/aws/cloudtrail/honeytoken"
CANARY_USER = "canary-backup-admin"
SECRET_NAME = "prod/db/master-password"
TOPIC = "honeytoken-alerts"
LAMBDA_NAME = "honeytoken-killswitch"
RULE_KEY = "honeytoken-canary-key"
RULE_BUCKET = "honeytoken-honey-bucket"
METRIC_FILTER = "CanaryAccessKeyUse"
ALARM = "honeytoken-canary-alarm"
CT_CW_ROLE = "CloudTrailToCloudWatchLogs"
LAMBDA_ROLE = "honeytoken-killswitch-role"
ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "maks.karakulinn@gmail.com")

iam = boto3.client("iam")
s3 = boto3.client("s3", region_name=REGION)
ct = boto3.client("cloudtrail", region_name=REGION)
logs = boto3.client("logs", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)
events = boto3.client("events", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)
sm = boto3.client("secretsmanager", region_name=REGION)


def log(msg):
    print(f"[deploy] {msg}", flush=True)


def canary_key_id():
    return canary_value("aws_access_key_id")


def canary_key_secret():
    return canary_value("aws_secret_access_key")


def canary_value(name):
    for line in (CANARY_DIR / "credentials").read_text().splitlines():
        if line.strip().startswith(name):
            return line.split("=", 1)[1].strip()
    raise RuntimeError(f"canary key file missing {name}")


def account_id():
    return ACCOUNT


# --------------------------------------------------------------------------
# guardrails: budget alarm
# --------------------------------------------------------------------------
def guardrails():
    budgets = boto3.client("budgets", region_name="us-east-1")
    try:
        budgets.describe_budget(AccountId=ACCOUNT, BudgetName="honeytoken-lab")
        log("budget honeytoken-lab already exists")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise
        budgets.create_budget(
            AccountId=ACCOUNT,
            Budget={
                "BudgetName": "honeytoken-lab",
                "BudgetLimit": {"Amount": "5", "Unit": "USD"},
                "TimeUnit": "MONTHLY",
                "BudgetType": "COST",
            },
        )
        log("created $5 monthly budget alarm")

    # notify the same topic once it exists (best effort, called again in detection)
    try:
        topic_arn = sns.create_topic(Name=TOPIC)["TopicArn"]
        budgets.create_notification(
            AccountId=ACCOUNT,
            BudgetName="honeytoken-lab",
            Notification={
                "NotificationType": "ACTUAL",
                "ComparisonOperator": "GREATER_THAN",
                "Threshold": 80.0,
                "ThresholdType": "PERCENTAGE",
            },
            Subscribers=[{"SubscriptionType": "SNS", "Address": topic_arn}],
        )
        log("budget notification wired to SNS")
    except Exception as e:  # pragma: no cover - notification already exists
        log(f"budget notification skipped: {e}")


# --------------------------------------------------------------------------
# deception layer
# --------------------------------------------------------------------------
def deception():
    # --- canary IAM user ------------------------------------------------
    try:
        iam.create_user(UserName=CANARY_USER, Tags=[{"Key": "purpose", "Value": "honeytoken-decoy"}])
        log(f"created IAM user {CANARY_USER}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        log(f"IAM user {CANARY_USER} already exists")

    deny_all = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "HoneytokenDenyAll", "Effect": "Deny", "Action": "*", "Resource": "*"}
        ],
    }
    iam.put_user_policy(
        UserName=CANARY_USER, PolicyName="deny-all", PolicyDocument=json.dumps(deny_all)
    )
    log("attached explicit deny-all inline policy")

    # --- canary access key ----------------------------------------------
    CANARY_DIR.mkdir(exist_ok=True)
    cred_file = CANARY_DIR / "credentials"
    if cred_file.exists():
        log("canary access key already generated (reusing .canary/credentials)")
        key_id = canary_key_id()
    else:
        keys = iam.list_access_keys(UserName=CANARY_USER)["AccessKeyMetadata"]
        for k in keys:
            iam.delete_access_key(UserName=CANARY_USER, AccessKeyId=k["AccessKeyId"])
        key = iam.create_access_key(UserName=CANARY_USER)["AccessKey"]
        key_id = key["AccessKeyId"]
        cred_file.write_text(
            "[canary]\n"
            f"aws_access_key_id = {key['AccessKeyId']}\n"
            f"aws_secret_access_key = {key['SecretAccessKey']}\n"
            f"region = {REGION}\n"
        )
        log(f"created canary access key {key_id}")

    # --- honey bucket ---------------------------------------------------
    try:
        s3.create_bucket(Bucket=HONEY_BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        log(f"created honey bucket {HONEY_BUCKET}")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
        log(f"honey bucket {HONEY_BUCKET} already exists")

    s3.put_public_access_block(
        Bucket=HONEY_BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(Bucket=HONEY_BUCKET, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(
        Bucket=HONEY_BUCKET,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    fake_creds = (
        "# production backup service account - do not rotate without change approval\n"
        f"AWS_ACCESS_KEY_ID={key_id}\n"
        f"AWS_SECRET_ACCESS_KEY={canary_key_secret()}\n"
        f"AWS_DEFAULT_REGION={REGION}\n"
        "# last rotated 2026-09-14 by backup-bot\n"
    )
    s3.put_object(
        Bucket=HONEY_BUCKET,
        Key="backup/credentials.txt",
        Body=fake_creds.encode(),
        ContentType="text/plain",
    )
    s3.put_object(
        Bucket=HONEY_BUCKET,
        Key="backup/db-dump-2026-09-01.enc",
        Body=b"\x00" * 2048,
        ContentType="application/octet-stream",
    )
    log("planted decoy credential file and fake backup object")

    # --- canary secret --------------------------------------------------
    try:
        sm.create_secret(
            Name=SECRET_NAME,
            Description="Honeytoken - deliberately fake production password",
            SecretString=json.dumps({"username": "admin", "password": "fake-p@ssw0rd-2026"}),
            Tags=[{"Key": "purpose", "Value": "honeytoken-decoy"}],
        )
        log(f"created Secrets Manager canary {SECRET_NAME}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceExistsException":
            raise
        log(f"secret {SECRET_NAME} already exists")

    print(json.dumps({"canary_access_key_id": key_id, "honey_bucket": HONEY_BUCKET}))


# --------------------------------------------------------------------------
# detection layer
# --------------------------------------------------------------------------
def _bucket_policy(bucket, trail_arn, prefix):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/{prefix}/AWSLogs/{ACCOUNT}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def detection():
    trail_arn = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/{TRAIL}"

    # --- log bucket -----------------------------------------------------
    try:
        s3.create_bucket(Bucket=LOG_BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        log(f"created trail log bucket {LOG_BUCKET}")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
        log(f"trail log bucket {LOG_BUCKET} already exists")

    s3.put_public_access_block(
        Bucket=LOG_BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    _bucket_policy(LOG_BUCKET, trail_arn, "AWSLogs")

    # --- CloudTrail -> CloudWatch Logs role -----------------------------
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        iam.create_role(
            RoleName=CT_CW_ROLE,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Allows CloudTrail to deliver events to CloudWatch Logs",
        )
        log(f"created role {CT_CW_ROLE}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
    iam.put_role_policy(
        RoleName=CT_CW_ROLE,
        PolicyName="cloudtrail-to-cwlogs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{LOG_GROUP}:log-stream:*",
                    }
                ],
            }
        ),
    )
    cw_role_arn = f"arn:aws:iam::{ACCOUNT}:role/{CT_CW_ROLE}"

    # --- log group ------------------------------------------------------
    try:
        logs.create_log_group(logGroupName=LOG_GROUP)
        log(f"created log group {LOG_GROUP}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
    logs.put_retention_policy(logGroupName=LOG_GROUP, retentionInDays=7)
    log_group_arn = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{LOG_GROUP}:*"

    # --- trail with management + S3 data events -------------------------
    selectors = [
        {
            "Name": "ManagementEvents",
            "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}],
        },
        {
            "Name": "HoneyBucketDataEvents",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                {"Field": "resources.ARN", "StartsWith": [f"arn:aws:s3:::{HONEY_BUCKET}/"]},
            ],
        },
    ]
    try:
        ct.create_trail(
            Name=TRAIL,
            S3BucketName=LOG_BUCKET,
            S3KeyPrefix="AWSLogs",
            IsMultiRegionTrail=True,
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=True,
            CloudWatchLogsLogGroupArn=log_group_arn,
            CloudWatchLogsRoleArn=cw_role_arn,
        )
        log(f"created trail {TRAIL}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "TrailAlreadyExistsException":
            raise
        ct.update_trail(
            Name=TRAIL,
            S3BucketName=LOG_BUCKET,
            S3KeyPrefix="AWSLogs",
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
            CloudWatchLogsLogGroupArn=log_group_arn,
            CloudWatchLogsRoleArn=cw_role_arn,
        )
        log(f"updated existing trail {TRAIL}")

    ct.put_event_selectors(TrailName=TRAIL, AdvancedEventSelectors=selectors)
    ct.start_logging(Name=TRAIL)
    log("trail logging started (management + honey bucket S3 data events)")

    # --- SNS ------------------------------------------------------------
    topic_arn = sns.create_topic(Name=TOPIC)["TopicArn"]
    log(f"SNS topic {topic_arn}")
    topic_arn = topic_arn.replace(":honeytoken-alerts", f":{TOPIC}")
    subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    if not any(s["Endpoint"] == ALERT_EMAIL for s in subs):
        sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=ALERT_EMAIL)
        log(f"subscribed {ALERT_EMAIL} (confirmation email sent)")
    else:
        log("email subscription already present")

    # --- metric filter + alarm -----------------------------------------
    canary_key = canary_key_id()

    try:
        logs.put_metric_filter(
            logGroupName=LOG_GROUP,
            filterName=METRIC_FILTER,
            filterPattern='{ ($.userIdentity.accessKeyId = "%s") }' % canary_key,
            metricTransformations=[
                {
                    "metricName": "CanaryKeyUsed",
                    "metricNamespace": "Honeytoken",
                    "metricValue": "1",
                    "defaultValue": 0,
                }
            ],
        )
        log(f"metric filter {METRIC_FILTER} created")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
        logs.put_metric_filter(
            logGroupName=LOG_GROUP,
            filterName=METRIC_FILTER,
            filterPattern='{ ($.userIdentity.accessKeyId = "%s") }' % canary_key,
            metricTransformations=[
                {
                    "metricName": "CanaryKeyUsed",
                    "metricNamespace": "Honeytoken",
                    "metricValue": "1",
                    "defaultValue": 0,
                }
            ],
        )
        log(f"metric filter {METRIC_FILTER} updated")

    cw.put_metric_alarm(
        AlarmName=ALARM,
        AlarmDescription="Canary AWS access key was used - honeytoken tripped",
        MetricName="CanaryKeyUsed",
        Namespace="Honeytoken",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        AlarmActions=[topic_arn],
    )
    log(f"alarm {ALARM} created (period 60s, threshold >= 1)")

    print(json.dumps({"topic_arn": topic_arn, "log_group": LOG_GROUP, "trail": TRAIL}))


# --------------------------------------------------------------------------
# response layer: EventBridge rules + kill-switch Lambda
# --------------------------------------------------------------------------
def _lambda_zip():
    import zipfile

    out = ROOT / ".canary" / "killswitch.zip"
    out.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(ROOT / "lambda" / "killswitch" / "handler.py", "handler.py")
    return out.read_bytes()


def _ensure_lambda_role(topic_arn, canary_user_arn):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        iam.create_role(
            RoleName=LAMBDA_ROLE,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Least privilege role for the honeytoken kill switch",
        )
        log(f"created role {LAMBDA_ROLE}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise

    iam.put_role_policy(
        RoleName=LAMBDA_ROLE,
        PolicyName="killswitch-least-privilege",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DeactivateCanaryKeyOnly",
                        "Effect": "Allow",
                        "Action": ["iam:UpdateAccessKey", "iam:ListAccessKeys"],
                        "Resource": canary_user_arn,
                    },
                    {
                        "Sid": "PublishAlert",
                        "Effect": "Allow",
                        "Action": "sns:Publish",
                        "Resource": topic_arn,
                    },
                    {
                        "Sid": "OwnLogs",
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{LAMBDA_NAME}:*",
                    },
                ],
            }
        ),
    )
    return f"arn:aws:iam::{ACCOUNT}:role/{LAMBDA_ROLE}"


def response():
    topic_arn = f"arn:aws:sns:{REGION}:{ACCOUNT}:{TOPIC}"
    canary_user_arn = f"arn:aws:iam::{ACCOUNT}:user/{CANARY_USER}"
    role_arn = _ensure_lambda_role(topic_arn, canary_user_arn)
    time.sleep(10)  # allow IAM propagation

    code = _lambda_zip()
    env = {"Variables": {"TOPIC_ARN": topic_arn, "CANARY_USER": CANARY_USER}}
    try:
        lam.create_function(
            FunctionName=LAMBDA_NAME,
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.lambda_handler",
            Code={"ZipFile": code},
            Timeout=15,
            MemorySize=128,
            Environment=env,
            Description="Deactivates the honeytoken access key and raises an SNS alert",
            Tags={"purpose": "honeytoken-response"},
        )
        log(f"created Lambda {LAMBDA_NAME}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceConflictException":
            raise
        lam.update_function_code(FunctionName=LAMBDA_NAME, ZipFile=code)
        time.sleep(5)
        lam.update_function_configuration(
            FunctionName=LAMBDA_NAME, Role=role_arn, Environment=env, Timeout=15
        )
        log(f"updated Lambda {LAMBDA_NAME}")

    fn_arn = lam.get_function(FunctionName=LAMBDA_NAME)["Configuration"]["FunctionArn"]

    # allow EventBridge to invoke
    for rule in (RULE_KEY, RULE_BUCKET):
        try:
            lam.add_permission(
                FunctionName=LAMBDA_NAME,
                StatementId=f"allow-eventbridge-{rule}",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=f"arn:aws:events:{REGION}:{ACCOUNT}:rule/{rule}",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceConflictException":
                raise

    canary_key = canary_key_id()

    rules = {
        RULE_KEY: {
            "source": ["aws.iam", "aws.s3", "aws.secretsmanager", "aws.sts"],
            "detail": {"userIdentity": {"accessKeyId": [canary_key]}},
        },
        RULE_BUCKET: {
            "source": ["aws.s3"],
            "detail": {
                "eventSource": ["s3.amazonaws.com"],
                "requestParameters": {"bucketName": [HONEY_BUCKET]},
            },
        },
    }
    for name, pattern in rules.items():
        events.put_rule(
            Name=name,
            EventPattern=json.dumps(pattern),
            State="ENABLED",
            Description="Honeytoken tripwire",
        )
        for idx, target in enumerate(
            [
                {"Id": "killswitch", "Arn": fn_arn},
                {"Id": "sns", "Arn": topic_arn},
            ]
        ):
            try:
                events.put_targets(Rule=name, Targets=[target])
            except ClientError as e:
                log(f"target {target['Id']} on {name}: {e}")
        log(f"EventBridge rule {name} enabled -> Lambda + SNS")

    print(json.dumps({"lambda_arn": fn_arn, "rules": list(rules)}))


if __name__ == "__main__":
    step = sys.argv[1] if len(sys.argv) > 1 else "all"
    steps = {
        "guardrails": guardrails,
        "deception": deception,
        "detection": detection,
        "response": response,
    }
    if step == "all":
        for fn in steps.values():
            fn()
    else:
        steps[step]()
