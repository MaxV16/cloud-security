"""Check whether the canary EventBridge rule actually received the S7/S8 events.

Prints the rule pattern, then the AWS/Events Invocations and FailedInvocations
metrics for the last hour, plus every Lambda log line from the kill switch.
"""
import time

import boto3

REGION = "eu-west-1"
RULE = "honeytoken-canary-key"
LAMBDA = "/aws/lambda/honeytoken-killswitch"

ev = boto3.client("events", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)
logs = boto3.client("logs", region_name=REGION)

rule = ev.describe_rule(Name=RULE)
print("PATTERN:", rule.get("EventPattern"))
print("STATE:", rule.get("State"), "arn:", rule.get("Arn"))
print("targets:", [t["Arn"] for t in ev.list_targets_by_rule(Rule=RULE)["Targets"]])

now = time.time()
for metric in ("Invocations", "FailedInvocations", "MatchedEvents"):
    resp = cw.get_metric_statistics(
        Namespace="AWS/Events", MetricName=metric,
        Dimensions=[{"Name": "RuleName", "Value": RULE}],
        StartTime=now - 5400, EndTime=now, Period=300, Statistics=["Sum"],
    )
    pts = sorted(resp["Datapoints"], key=lambda p: p["Timestamp"])
    print(f"\n{metric}:")
    for p in pts:
        print("  ", p["Timestamp"].strftime("%H:%M"), int(p["Sum"]))

print("\nLambda invocations (Last 1h):")
resp = cw.get_metric_statistics(
    Namespace="AWS/Lambda", MetricName="Invocations",
    Dimensions=[{"Name": "FunctionName", "Value": "honeytoken-killswitch"}],
    StartTime=now - 5400, EndTime=now, Period=300, Statistics=["Sum"],
)
for p in sorted(resp["Datapoints"], key=lambda p: p["Timestamp"]):
    print("  ", p["Timestamp"].strftime("%H:%M"), int(p["Sum"]))

print("\nLambda log lines:")
streams = logs.describe_log_streams(logGroupName=LAMBDA, orderBy="LastEventTime", descending=True, limit=10)
for s in streams["logStreams"]:
    evs = logs.get_log_events(logGroupName=LAMBDA, logStreamName=s["logStreamName"], limit=50)
    for e in evs["events"]:
        msg = e["message"].strip()
        if "START" in msg or "END" in msg or "REPORT" in msg:
            continue
        ts = time.strftime("%H:%M:%S", time.gmtime(e["timestamp"] / 1000))
        print(f"  {ts} {msg[:220]}")
