import datetime
import json

import boto3

logs = boto3.client("logs", region_name="eu-west-1")
streams = logs.describe_log_streams(
    logGroupName="/aws/lambda/honeytoken-killswitch", orderBy="LastEventTime", descending=True
)["logStreams"]
for s in streams:
    ev = logs.get_log_events(
        logGroupName="/aws/lambda/honeytoken-killswitch", logStreamName=s["logStreamName"]
    )["events"]
    print("==", s["logStreamName"])
    for e in ev:
        ts = datetime.datetime.fromtimestamp(e["timestamp"] / 1000, datetime.timezone.utc)
        print("  ", ts.isoformat(), e["message"].strip()[:220])
