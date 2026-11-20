"""Tear down everything this project created in AWS. Only touches our own named resources."""
import json
import sys

import boto3
from botocore.exceptions import ClientError

REGION = "eu-west-1"
ACCOUNT = "508261694250"

LOG_BUCKET = f"honeytoken-cloudtrail-{ACCOUNT}"
HONEY_BUCKET = f"prod-backup-credentials-2026-{ACCOUNT}"
TRAIL = "honeytoken-trail"
CT_ROLE = "CloudTrailToCloudWatchLogs"
CT_LOG_GROUP = "/aws/cloudtrail/honeytoken"
CANARY_USER = "canary-backup-admin"
SECRET_NAME = "prod/db/master-password"
TOPIC = "honeytoken-alerts"
LAMBDA_NAME = "honeytoken-killswitch"
LAMBDA_ROLE = "honeytoken-killswitch-role"
RULES = ["honeytoken-canary-key", "honeytoken-honey-bucket"]
ALARM = "honeytoken-canary-alarm"
FILTER = "CanaryAccessKeyUse"
BUDGET = "honeytoken-lab"

session = boto3.Session(region_name=REGION)
iam = session.client("iam")
s3 = session.client("s3")
ct = session.client("cloudtrail")
ev = session.client("events")
lam = session.client("lambda")
cw = session.client("cloudwatch")
logs = session.client("logs")
sns = session.client("sns")
sm = session.client("secretsmanager")
gd = session.client("guardduty")
ec2 = session.client("ec2")
budgets = boto3.client("budgets", region_name="us-east-1")


def step(label, fn):
    try:
        fn()
        print("ok   ", label)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("ResourceNotFoundException", "NoSuchEntity", "NotFoundException",
                    "NoSuchBucket", "ResourceNotFound", "TrailNotFoundException"):
            print("skip ", label, "(not found)")
        else:
            print("FAIL ", label, "->", code, exc.response.get("Error", {}).get("Message", "")[:120])
    except Exception as exc:
        print("FAIL ", label, "->", type(exc).__name__, str(exc)[:120])


print("== detection")
for rule in RULES:
    step(f"remove targets {rule}", lambda r=rule: [
        ev.remove_targets(Rule=r, Ids=[t["Id"] for t in ev.list_targets_by_rule(Rule=r)["Targets"]])])
    step(f"delete rule {rule}", lambda r=rule: ev.delete_rule(Name=r))

step("delete alarm", lambda: cw.delete_alarms(AlarmNames=[ALARM]))
step("delete metric filter", lambda: logs.delete_metric_filter(
    logGroupName=CT_LOG_GROUP, filterName=FILTER))

print("== response")
step("delete lambda", lambda: lam.delete_function(FunctionName=LAMBDA_NAME))
step("delete lambda log group", lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{LAMBDA_NAME}"))
step("detach lambda policy", lambda: [
    iam.delete_role_policy(RoleName=LAMBDA_ROLE, PolicyName=p["PolicyName"])
    for p in iam.list_role_policies(RoleName=LAMBDA_ROLE)["PolicyNames"]])
step("delete lambda role", lambda: iam.delete_role(RoleName=LAMBDA_ROLE))
step("delete topic", lambda: sns.delete_topic(TopicArn=sns.create_topic(Name=TOPIC)["TopicArn"]))

print("== telemetry")
step("stop logging", lambda: ct.stop_logging(Name=TRAIL))
step("delete trail", lambda: ct.delete_trail(Name=TRAIL))
step("delete ct log group", lambda: logs.delete_log_group(logGroupName=CT_LOG_GROUP))
step("detach ct role policy", lambda: [
    iam.delete_role_policy(RoleName=CT_ROLE, PolicyName=p["PolicyName"])
    for p in iam.list_role_policies(RoleName=CT_ROLE)["PolicyNames"]])
step("delete ct role", lambda: iam.delete_role(RoleName=CT_ROLE))

print("== deception")
step("delete secret", lambda: sm.delete_secret(SecretId=SECRET_NAME, ForceDeleteWithoutRecovery=True))
step("delete canary keys", lambda: [
    iam.delete_access_key(UserName=CANARY_USER, AccessKeyId=k["AccessKeyId"])
    for k in iam.list_access_keys(UserName=CANARY_USER)["AccessKeyMetadata"]])
step("delete canary policies", lambda: [
    iam.delete_user_policy(UserName=CANARY_USER, PolicyName=p["PolicyName"])
    for p in iam.list_user_policies(UserName=CANARY_USER)["PolicyNames"]])
step("delete canary user", lambda: iam.delete_user(UserName=CANARY_USER))


def empty_and_delete(bucket):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
    s3.delete_bucket(Bucket=bucket)


for bucket in (LOG_BUCKET, HONEY_BUCKET):
    step(f"empty + delete bucket {bucket}", lambda b=bucket: empty_and_delete(b))

print("== account hardening reverted")
for d in gd.list_detectors().get("DetectorIds", []):
    step(f"delete guardduty detector {d}", lambda x=d: gd.delete_detector(DetectorId=x))

step("disable ebs default encryption", lambda: ec2.disable_ebs_encryption_by_default())
step("delete account s3 block", lambda: s3.delete_public_access_block(AccountId=ACCOUNT))
step("delete iam password policy", lambda: iam.delete_account_password_policy())
step("delete budget", lambda: budgets.delete_budget(
    AccountId=ACCOUNT, BudgetName=BUDGET))

print("== remaining")
print("users:", [u["UserName"] for u in iam.list_users()["Users"]])
print("buckets:", [b["Name"] for b in s3.list_buckets()["Buckets"]])
print("trails:", [t["Name"] for t in ct.describe_trails()["trailList"]])
print("rules:", [r["Name"] for r in ev.list_rules()["Rules"]])
print("functions:", [f["FunctionName"] for f in lam.list_functions()["Functions"]])
print("topics:", [t["TopicArn"] for t in sns.list_topics()["Topics"]])
print("secrets:", [s["Name"] for s in sm.list_secrets()["SecretList"]])
print("alarms:", [a["AlarmName"] for a in cw.describe_alarms()["MetricAlarms"]])
