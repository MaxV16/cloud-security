"""Fire one matched call with the canary key and confirm both rule targets
(Lambda and SNS) now succeed, i.e. FailedInvocations stays at zero.

Run: python scripts/verify_targets.py
"""
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

REGION = "eu-west-1"
RULE = "honeytoken-canary-key"


def canary_value(name):
    path = r".canary\credentials"
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if "=" in line:
                k, v = line.split("=", 1)
                if k.strip() == name:
                    return v.strip()
    raise KeyError(name)


key = canary_value("aws_access_key_id")
secret = canary_value("aws_secret_access_key")

iam = boto3.client("iam")
iam.update_access_key(UserName="canary-backup-admin", AccessKeyId=key, Status="Active")
print("key re-armed, waiting 20 s for propagation")
time.sleep(20)

for attempt in range(10):
    sts = boto3.client(
        "sts",
        region_name=REGION,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
    )
    try:
        ident = sts.get_caller_identity()
        print("call succeeded at", datetime.now(timezone.utc).isoformat())
        break
    except ClientError as exc:
        print("attempt", attempt, exc.response["Error"]["Code"])
        time.sleep(20)
else:
    raise SystemExit("could not get a successful call")

time.sleep(90)

cw = boto3.client("cloudwatch", region_name=REGION)
end = datetime.now(timezone.utc)
start = end - timedelta(minutes=15)


def total(metric):
    resp = cw.get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": "RuleName", "Value": RULE}],
        StartTime=start,
        EndTime=end,
        Period=300,
        Statistics=["Sum"],
    )
    return sum(d["Sum"] for d in resp["Datapoints"])


print("MatchedEvents     ", total("MatchedEvents"))
print("Invocations       ", total("Invocations"))
print("FailedInvocations ", total("FailedInvocations"))

iam.update_access_key(UserName="canary-backup-admin", AccessKeyId=key, Status="Inactive")
print("key set back to Inactive")
