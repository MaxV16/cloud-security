"""Dump every message in the catch-all log groups, unfiltered."""
import json

import boto3

for region in ("eu-west-1", "us-east-1"):
    logs = boto3.client("logs", region_name=region)
    group = "/aws/events/honeytoken-catchall"
    print(f"\n=== {region} ===")
    streams = logs.describe_log_streams(logGroupName=group, orderBy="LastEventTime",
                                        descending=True, limit=10)["logStreams"]
    print("streams:", len(streams))
    for s in streams:
        for e in logs.get_log_events(logGroupName=group, logStreamName=s["logStreamName"])["events"]:
            msg = e["message"]
            try:
                rec = json.loads(msg)
                d = rec.get("detail", {})
                print(f"{d.get('eventTime')} {d.get('eventName')} err={d.get('errorCode')} "
                      f"ident={json.dumps(d.get('userIdentity'))[:200]}")
            except ValueError:
                print(msg[:300])
