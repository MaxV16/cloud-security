"""Evaluate the canary rule pattern against the real CloudTrail records.

test_event_pattern has no side effects: it only tells us whether EventBridge
would consider a given event a match. We wrap each stored CloudTrail record in
the standard CloudTrail envelope that EventBridge uses.
"""
import json

import boto3

REGION = "eu-west-1"
RULE = "honeytoken-canary-key"

ev = boto3.client("events", region_name=REGION)
pattern = ev.describe_rule(Name=RULE)["EventPattern"]

records = json.load(open("evidence/canary_events.json"))
for rec in records:
    source = "aws." + rec["eventSource"].split(".")[0]
    envelope = {
        "version": "0",
        "id": "test",
        "detail-type": "AWS API Call via CloudTrail",
        "source": source,
        "account": "508261694250",
        "time": rec["eventTime"],
        "region": rec["awsRegion"],
        "resources": [],
        "detail": rec,
    }
    resp = ev.test_event_pattern(EventPattern=pattern, Event=json.dumps(envelope, default=str))
    print(f"{rec['eventTime']}  {rec['eventName']:<20} source={source:<14} "
          f"error={rec.get('errorCode')}  match={resp['Result']}")

# Now a hard-coded envelope that mirrors what EventBridge actually delivers for a
# denied S3 call, to see whether the AccessDenied flag itself is the problem.
print()
for err in (None, "AccessDenied"):
    detail = {
        "eventVersion": "1.09",
        "userIdentity": {"type": "IAMUser", "accessKeyId": "AKIAXMVWB7MVLTPKSPCX"},
        "eventTime": "2026-11-21T06:22:25Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "ListBuckets",
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "185.99.26.161",
    }
    if err:
        detail["errorCode"] = err
        detail["errorMessage"] = "Access Denied"
    envelope = {"source": "aws.s3", "detail-type": "AWS API Call via CloudTrail", "detail": detail}
    resp = ev.test_event_pattern(EventPattern=pattern, Event=json.dumps(envelope))
    print(f"synthetic ListBuckets error={err}: match={resp['Result']}")
