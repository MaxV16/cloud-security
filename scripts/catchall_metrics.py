"""Metrics for the catch-all rules: matched, invoked, failed."""
import time

import boto3

now = time.time()
for region in ("eu-west-1", "us-east-1"):
    cw = boto3.client("cloudwatch", region_name=region)
    print(f"\n=== {region} ===")
    for metric in ("MatchedEvents", "Invocations", "FailedInvocations"):
        resp = cw.get_metric_statistics(
            Namespace="AWS/Events", MetricName=metric,
            Dimensions=[{"Name": "RuleName", "Value": "honeytoken-catchall"}],
            StartTime=now - 3600, EndTime=now, Period=300, Statistics=["Sum"],
        )
        pts = sorted(resp["Datapoints"], key=lambda p: p["Timestamp"])
        print(f"{metric}: " + ", ".join(f"{p['Timestamp'].strftime('%H:%M')}={int(p['Sum'])}" for p in pts))
