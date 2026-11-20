"""Where do CloudTrail records for global-service calls actually reach EventBridge?

Two trials in the main run were never matched by the canary rule in eu-west-1:
ListBuckets (S7) and ListUsers (S8). test_event_pattern says the pattern matches
both stored records, and the rule's MatchedEvents metric stays at zero, so the
question is delivery rather than matching.

This script puts an identical rule on the us-east-1 default bus with a CloudWatch
Logs target, repeats both calls with the canary credentials and reports which
events landed in us-east-1, plus the matched-event counts on both buses.
"""
import json
import sys
import time

import boto3

sys.path.insert(0, __file__.rsplit("\\", 1)[0] + "\\..\\infra")
from deploy import canary_key_id, canary_key_secret  # noqa: E402

HOME = "eu-west-1"
EAST = "us-east-1"
LOG_GROUP = "/aws/events/honeytoken-global-test"
RULE = "honeytoken-canary-global-test"
EU_RULE = "honeytoken-canary-key"

key_id = canary_key_id()
secret = canary_key_secret()
pattern = json.dumps({
    "source": ["aws.iam", "aws.s3", "aws.secretsmanager", "aws.sts"],
    "detail": {"userIdentity": {"accessKeyId": [key_id]}},
})

account = boto3.client("sts", region_name=HOME).get_caller_identity()["Account"]
logs_east = boto3.client("logs", region_name=EAST)
events_east = boto3.client("events", region_name=EAST)
cw_home = boto3.client("cloudwatch", region_name=HOME)
iam = boto3.client("iam", region_name=HOME)

# 1. log group + resource policy so EventBridge may write to it
try:
    logs_east.create_log_group(logGroupName=LOG_GROUP)
except logs_east.exceptions.ResourceAlreadyExistsException:
    pass
group_arn = logs_east.describe_log_groups(logGroupNamePrefix=LOG_GROUP)["logGroups"][0]["arn"].rstrip(":*")
rule_arn = f"arn:aws:events:{EAST}:{account}:rule/{RULE}"
policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "EventBridgeWrite",
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": group_arn + ":*",
        "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
    }],
}
logs_east.put_resource_policy(policyName="EventBridgeWrite", policyDocument=json.dumps(policy))

# 2. the throwaway rule in us-east-1
events_east.put_rule(Name=RULE, EventPattern=pattern, State="ENABLED",
                     Description="Temporary: global-service event routing test")
events_east.put_targets(Rule=RULE, Targets=[{"Id": "loggroup", "Arn": group_arn + ":*"}])
print("rule", RULE, "created on the us-east-1 bus")

iam.update_access_key(UserName="canary-backup-admin", AccessKeyId=key_id, Status="Active")

canary_iam = boto3.client("iam", region_name=HOME, aws_access_key_id=key_id, aws_secret_access_key=secret)
canary_s3 = boto3.client("s3", region_name=HOME, aws_access_key_id=key_id, aws_secret_access_key=secret)

calls = []
for label, fn in (("ListUsers (IAM)", canary_iam.list_users),
                  ("ListBuckets (S3)", canary_s3.list_buckets)):
    print(f"\ncalling {label} with the canary key")
    started = time.time()
    try:
        fn()
        print("  call unexpectedly succeeded")
    except Exception as exc:  # noqa: BLE001
        print("  ", type(exc).__name__, getattr(exc, "response", {}).get("Error", {}).get("Code"))
    calls.append({"label": label, "ts": started})
    print("  waiting 90 s for delivery")
    time.sleep(90)


def matched(client, rule, since):
    resp = client.get_metric_statistics(
        Namespace="AWS/Events", MetricName="MatchedEvents",
        Dimensions=[{"Name": "RuleName", "Value": rule}],
        StartTime=since - 600, EndTime=time.time() + 120, Period=300, Statistics=["Sum"],
    )
    return [[p["Timestamp"].strftime("%H:%M"), int(p["Sum"])]
            for p in sorted(resp["Datapoints"], key=lambda p: p["Timestamp"])]


first = calls[0]["ts"]
result = {
    "eu_matched": matched(cw_home, EU_RULE, first),
    "us_matched": matched(events_east, RULE, first),
    "delivered": [],
}
print("\nMatchedEvents on the eu-west-1 rule:", result["eu_matched"])
print("MatchedEvents on the us-east-1 rule:", result["us_matched"])

# 3. what arrived on the us-east-1 bus?
try:
    streams = logs_east.describe_log_streams(logGroupName=LOG_GROUP, orderBy="LastEventTime",
                                             descending=True, limit=5)["logStreams"]
    for s in streams:
        for e in logs_east.get_log_events(logGroupName=LOG_GROUP, logStreamName=s["logStreamName"])["events"]:
            try:
                rec = json.loads(e["message"])
                detail = rec.get("detail", {})
                if (detail.get("userIdentity") or {}).get("accessKeyId") != key_id:
                    continue
                row = {
                    "eventTime": detail.get("eventTime"),
                    "eventName": detail.get("eventName"),
                    "eventSource": detail.get("eventSource"),
                    "awsRegion": detail.get("awsRegion"),
                    "errorCode": detail.get("errorCode"),
                    "seconds_after_call": round(e["timestamp"] / 1000 - first, 1),
                }
                print("DELIVERED on us-east-1:", row)
                result["delivered"].append(row)
            except ValueError:
                continue
except Exception as exc:  # noqa: BLE001
    print("could not read log group:", exc)

with open("evidence/global_service.json", "w", encoding="utf-8") as fh:
    json.dump(result, fh, indent=2, default=str)
print("\nwrote evidence/global_service.json")
