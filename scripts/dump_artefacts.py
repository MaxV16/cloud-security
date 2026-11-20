"""Dump the configuration of the deployed pieces to evidence/artefacts.json."""
import json
from pathlib import Path

import boto3

R = "eu-west-1"
out = {}

ct = boto3.client("cloudtrail", region_name=R)
out["trail"] = {
    k: v
    for k, v in ct.get_trail(Name="honeytoken-trail")["Trail"].items()
    if k in ("Name", "S3BucketName", "CloudWatchLogsLogGroupArn", "IsMultiRegionTrail", "HomeRegion", "LogFileValidationEnabled")
}
out["selectors"] = ct.get_event_selectors(TrailName="honeytoken-trail")["AdvancedEventSelectors"]

ev = boto3.client("events", region_name=R)
out["rules"] = {}
for name in ("honeytoken-canary-key", "honeytoken-honey-bucket"):
    d = ev.describe_rule(Name=name)
    out["rules"][name] = {"pattern": json.loads(d["EventPattern"]), "state": d["State"], "targets": ev.list_targets_by_rule(Rule=name)["Targets"]}

lam = boto3.client("lambda", region_name=R)
cfg = lam.get_function(FunctionName="honeytoken-killswitch")["Configuration"]
out["lambda"] = {k: cfg.get(k) for k in ("FunctionName", "Runtime", "MemorySize", "Timeout", "LastModified")}
out["lambda"]["policy"] = lam.get_policy(FunctionName="honeytoken-killswitch")["Policy"]

cw = boto3.client("cloudwatch", region_name=R)
alarms = cw.describe_alarms(AlarmNames=["honeytoken-canary-alarm"])["MetricAlarms"][0]
out["alarm"] = {k: alarms.get(k) for k in ("AlarmName", "MetricName", "Namespace", "Statistic", "Period", "EvaluationPeriods", "Threshold", "ComparisonOperator", "TreatMissingData", "StateValue")}

lg = boto3.client("logs", region_name=R)
filters = lg.describe_metric_filters(logGroupName="/aws/cloudtrail/honeytoken")["metricFilters"]
out["metric_filter"] = filters[0]["filterPattern"] if filters else None

iam = boto3.client("iam", region_name=R)
out["canary_user"] = {
    "keys": iam.list_access_keys(UserName="canary-backup-admin")["AccessKeyMetadata"],
    "policies": iam.list_user_policies(UserName="canary-backup-admin")["PolicyNames"],
    "attached": iam.list_attached_user_policies(UserName="canary-backup-admin")["AttachedPolicies"],
    "tags": iam.list_user_tags(UserName="canary-backup-admin")["Tags"],
}
out["deny_policy"] = iam.get_user_policy(UserName="canary-backup-admin", PolicyName="deny-all")["PolicyDocument"]
out["role_policy"] = iam.get_role_policy(RoleName="honeytoken-killswitch-role", PolicyName="killswitch-least-privilege")["PolicyDocument"]

sns = boto3.client("sns", region_name=R)
subs = sns.list_subscriptions_by_topic(TopicArn="arn:aws:sns:eu-west-1:508261694250:honeytoken-alerts")["Subscriptions"]
out["subscriptions"] = [{k: s.get(k) for k in ("Protocol", "Endpoint", "SubscriptionArn")} for s in subs]

s3 = boto3.client("s3", region_name=R)
out["honey_bucket_objects"] = [
    {"Key": o["Key"], "Size": o["Size"], "LastModified": o["LastModified"].isoformat()} for o in s3.list_objects_v2(Bucket="prod-backup-credentials-2026-508261694250").get("Contents", [])
]
out["honey_bucket_config"] = {
    "versioning": s3.get_bucket_versioning(Bucket="prod-backup-credentials-2026-508261694250").get("Status"),
    "public_access_block": s3.get_public_access_block(Bucket="prod-backup-credentials-2026-508261694250")["PublicAccessBlockConfiguration"],
    "encryption": s3.get_bucket_encryption(Bucket="prod-backup-credentials-2026-508261694250")["ServerSideEncryptionConfiguration"],
}

Path("evidence").mkdir(exist_ok=True)
Path("evidence/artefacts.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
print("wrote evidence/artefacts.json")
print(json.dumps(out["metric_filter"]))
print(json.dumps(out["rules"]["honeytoken-canary-key"]["pattern"], indent=2))
print("alarm:", out["alarm"]["StateValue"], "| keys:", [(k["AccessKeyId"], k["Status"]) for k in out["canary_user"]["keys"]])
