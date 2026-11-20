"""Do denied management events reach EventBridge at all?

Makes a denied management call as the administrator (AssumeRole on a role that
does not exist), waits, then prints what the catch-all rules received.
"""
import json
import time

import boto3

sts = boto3.client("sts", region_name="eu-west-1")
try:
    sts.assume_role(RoleArn="arn:aws:iam::508261694250:role/does-not-exist",
                    RoleSessionName="probe")
    print("assume_role unexpectedly succeeded")
except Exception as exc:  # noqa: BLE001
    print("denied as expected:", exc.response["Error"]["Code"])

time.sleep(60)

for region in ("eu-west-1", "us-east-1"):
    logs = boto3.client("logs", region_name=region)
    group = "/aws/events/honeytoken-catchall"
    print(f"\n=== {region} ===")
    streams = logs.describe_log_streams(logGroupName=group, orderBy="LastEventTime",
                                        descending=True, limit=10)["logStreams"]
    for s in streams:
        for e in logs.get_log_events(logGroupName=group, logStreamName=s["logStreamName"],
                                     startTime=int(time.time() * 1000) - 300000)["events"]:
            try:
                d = json.loads(e["message"]).get("detail", {})
            except ValueError:
                continue
            print(f"{d.get('eventTime')} {d.get('eventName'):<22} err={d.get('errorCode')} "
                  f"key={(d.get('userIdentity') or {}).get('accessKeyId')}")
