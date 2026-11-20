"""Dump the key CloudTrail fields for every canary-key event found in the log group.

Used to explain why the EventBridge rule matched some calls but not others:
we print awsRegion, eventSource, readOnly, errorCode and the full JSON.
"""
import json
import sys
import time

import boto3

sys.path.insert(0, __file__.rsplit("\\", 1)[0] + "\\..\\infra")
from deploy import canary_key_id  # noqa: E402

REGION = "eu-west-1"
LOG_GROUP = "/aws/cloudtrail/honeytoken"

logs = boto3.client("logs", region_name=REGION)
key = canary_key_id()

start = int((time.time() - 7200) * 1000)
events = []
token = None
while True:
    kw = dict(logGroupName=LOG_GROUP, startTime=start, interleaved=True)
    if token:
        kw["nextToken"] = token
    resp = logs.filter_log_events(**kw)
    for e in resp.get("events", []):
        try:
            rec = json.loads(e["message"])
        except Exception:
            continue
        ui = rec.get("userIdentity", {})
        if ui.get("accessKeyId") == key:
            events.append(rec)
    token = resp.get("nextToken")
    if not token:
        break

print(f"{len(events)} canary events\n")
for rec in events:
    print(rec.get("eventTime"), rec.get("eventName"), "region=", rec.get("awsRegion"),
          "source=", rec.get("eventSource"), "error=", rec.get("errorCode"),
          "managementEvent=", rec.get("managementEvent"), "readOnly=", rec.get("readOnly"))

with open("evidence/canary_events.json", "w") as fh:
    json.dump(events, fh, indent=2, default=str)
print("\nwrote evidence/canary_events.json")
