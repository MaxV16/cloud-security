"""Remove the temporary probe rules and log groups created during the
Path A investigation, and publish the SNS topic policy that lets EventBridge
deliver directly to the alert topic.

Run: python scripts/cleanup_probes.py
"""
import json

import boto3
from botocore.exceptions import ClientError

REGION = "eu-west-1"
TOPIC_ARN = "arn:aws:sns:eu-west-1:508261694250:honeytoken-alerts"

RULES = [
    ("eu-west-1", "honeytoken-catchall", "/aws/events/honeytoken-catchall"),
    ("us-east-1", "honeytoken-catchall", "/aws/events/honeytoken-catchall"),
    ("us-east-1", "honeytoken-global-test", "/aws/events/honeytoken-global-test"),
]


def remove_targets(events, rule):
    try:
        targets = events.list_targets_by_rule(Rule=rule)["Targets"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    if targets:
        ids = [{"Id": t["Id"]} for t in targets]
        events.remove_targets(Rule=rule, Ids=[i["Id"] for i in ids])
    return True


def main():
    for region, rule, log_group in RULES:
        events = boto3.client("events", region_name=region)
        logs = boto3.client("logs", region_name=region)

        if remove_targets(events, rule):
            events.delete_rule(Name=rule)
            print(f"deleted rule {rule} ({region})")
        else:
            print(f"rule {rule} ({region}) already gone")

        try:
            logs.delete_log_group(logGroupName=log_group)
            print(f"deleted log group {log_group} ({region})")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            print(f"log group {log_group} ({region}) already gone")

    # Allow EventBridge to publish straight to the alert topic for the two
    # canary rules. Without this the rule's SNS target fails every time the
    # rule matches, which shows up as FailedInvocations in the AWS/Events metrics.
    sns = boto3.client("sns", region_name=REGION)
    account = boto3.client("sts").get_caller_identity()["Account"]
    statements = []
    for sid, rule in (
        ("EventBridgeCanaryKey", "honeytoken-canary-key"),
        ("EventBridgeHoneyBucket", "honeytoken-honey-bucket"),
    ):
        statements.append(
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": TOPIC_ARN,
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:events:{REGION}:{account}:rule/{rule}"
                    }
                },
            }
        )
    # Keep the existing statements (the default one is what lets the Lambda
    # role and our own CLI publish) and add the two EventBridge statements.
    current = json.loads(sns.get_topic_attributes(TopicArn=TOPIC_ARN)["Attributes"]["Policy"])
    keep = [s for s in current.get("Statement", []) if s.get("Sid") not in
            {"EventBridgeCanaryKey", "EventBridgeHoneyBucket"}]
    current["Statement"] = keep + statements
    sns.set_topic_attributes(
        TopicArn=TOPIC_ARN,
        AttributeName="Policy",
        AttributeValue=json.dumps(current),
    )
    print("topic policy updated")

    # Remaining rules, for the record.
    events = boto3.client("events", region_name=REGION)
    print("remaining rules in eu-west-1:")
    for rule in events.list_rules()["Rules"]:
        print(" -", rule["Name"], rule["State"])


if __name__ == "__main__":
    main()
