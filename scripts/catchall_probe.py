"""Catch-all probe: what does EventBridge actually receive for a denied call?

The canary rule (source list + detail.userIdentity.accessKeyId) matched a call
that succeeded and none of the calls that were denied, even though
test-event-pattern matches the stored trail records. To separate "not delivered"
from "not matched", this script puts a rule with no detail condition on both the
eu-west-1 and us-east-1 buses, writes matches to a log group on each bus, repeats
three denied calls and then prints the delivered JSON next to the trail record.
"""
import json
import sys
import time
from datetime import timezone

import boto3

sys.path.insert(0, __file__.rsplit("\\", 1)[0] + "\\..\\infra")
from deploy import canary_key_id, canary_key_secret  # noqa: E402

HOME = "eu-west-1"
EAST = "us-east-1"
RULE = "honeytoken-catchall"
PATTERN = json.dumps({"source": ["aws.s3", "aws.iam", "aws.ec2", "aws.sts", "aws.secretsmanager"]})
KEY_ID = canary_key_id()
SECRET = canary_key_secret()
ACCOUNT = boto3.client("sts", region_name=HOME).get_caller_identity()["Account"]

setups = {}
for region in (HOME, EAST):
    logs = boto3.client("logs", region_name=region)
    events = boto3.client("events", region_name=region)
    group = f"/aws/events/{RULE}"
    try:
        logs.create_log_group(logGroupName=group)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"].rstrip(":*")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "EventBridgeWrite",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": arn + ":*",
            "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:events:{region}:{ACCOUNT}:rule/{RULE}"}},
        }],
    }
    logs.put_resource_policy(policyName="EventBridgeWrite", policyDocument=json.dumps(policy))
    events.put_rule(Name=RULE, EventPattern=PATTERN, State="ENABLED",
                    Description="Temporary catch-all probe")
    events.put_targets(Rule=RULE, Targets=[{"Id": "loggroup", "Arn": arn + ":*"}])
    setups[region] = (logs, group)
    print("catch-all rule active on the", region, "bus")

creds = {"aws_access_key_id": KEY_ID, "aws_secret_access_key": SECRET, "region_name": HOME}
clients = {
    "ListUsers": boto3.client("iam", **creds),
    "ListBuckets": boto3.client("s3", **creds),
    "DescribeInstances": boto3.client("ec2", **creds),
}
boto3.client("iam", region_name=HOME).update_access_key(
    UserName="canary-backup-admin", AccessKeyId=KEY_ID, Status="Active")

for label, client in clients.items():
    method = {"ListUsers": "list_users", "ListBuckets": "list_buckets",
              "DescribeInstances": "describe_instances"}[label]
    try:
        getattr(client, method)()
        print(label, "succeeded")
    except Exception as exc:  # noqa: BLE001
        print(label, "->", getattr(exc, "response", {}).get("Error", {}).get("Code"))
    time.sleep(45)

for region, (logs, group) in setups.items():
    print(f"\n=== delivered on the {region} bus ===")
    streams = logs.describe_log_streams(logGroupName=group, orderBy="LastEventTime",
                                        descending=True, limit=5)["logStreams"]
    if not streams:
        print("nothing")
    for s in streams:
        for e in logs.get_log_events(logGroupName=group, logStreamName=s["logStreamName"])["events"]:
            try:
                rec = json.loads(e["message"])
            except ValueError:
                continue
            detail = rec.get("detail", {})
            if (detail.get("userIdentity") or {}).get("accessKeyId") != KEY_ID:
                continue
            print(f"{detail.get('eventTime')} {detail.get('eventName')} "
                  f"error={detail.get('errorCode')} userIdentity={json.dumps(detail.get('userIdentity'))}")
