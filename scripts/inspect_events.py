"""Ad-hoc helper: dump honeytoken related CloudTrail events from the log group."""
import datetime
import json
import sys

import boto3

logs = boto3.client("logs", region_name="eu-west-1")
LOG_GROUP = "/aws/cloudtrail/honeytoken"


def dump(pattern, limit=20):
    r = logs.filter_log_events(logGroupName=LOG_GROUP, filterPattern=pattern, limit=limit)
    for e in r["events"]:
        d = json.loads(e["message"])
        ts = datetime.datetime.utcfromtimestamp(e["timestamp"] / 1000).isoformat()
        ing = datetime.datetime.utcfromtimestamp(e["ingestionTime"] / 1000).isoformat()
        print(
            f"{ts}  ing={ing}  {d.get('eventName')}  err={d.get('errorCode')}  "
            f"key={d.get('userIdentity', {}).get('accessKeyId')}  "
            f"bucket={(d.get('requestParameters') or {}).get('bucketName')}  "
            f"ip={d.get('sourceIPAddress')}"
        )


if __name__ == "__main__":
    dump(sys.argv[1] if len(sys.argv) > 1 else "", int(sys.argv[2]) if len(sys.argv) > 2 else 20)
