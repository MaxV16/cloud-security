"""Collect timing evidence from the deployed honeytoken pipeline.

Reads CloudTrail Event History, the CloudWatch Logs copy of the same trail,
the kill-switch Lambda logs and the CloudWatch alarm history, then works out
how long each detection path took.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3

REGION = "eu-west-1"
LOG_GROUP = "/aws/cloudtrail/honeytoken"
LAMBDA_GROUP = "/aws/lambda/honeytoken-killswitch"
ALARM = "honeytoken-canary-alarm"
CANARY_USER = "canary-backup-admin"

ct = boto3.client("cloudtrail", region_name=REGION)
logs = boto3.client("logs", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)

now = datetime.now(timezone.utc)
start = now - timedelta(hours=6)


def parse(ts):
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


out = {"generated_utc": now.isoformat(), "region": REGION}


def ct_events():
    events = []
    for page in ct.get_paginator("lookup_events").paginate(
        StartTime=start, EndTime=now, LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": CANARY_USER}]
    ):
        for e in page["Events"]:
            events.append(
                {
                    "id": e["EventId"],
                    "time": parse(e["EventTime"]).isoformat(),
                    "name": e["EventName"],
                    "source": e["EventSource"],
                    "raw": json.loads(e["CloudTrailEvent"]),
                }
            )
    return events


def logs_events():
    rows = []
    token = None
    while True:
        kw = dict(logGroupName=LOG_GROUP, startTime=int(start.timestamp() * 1000), limit=500)
        if token:
            kw["nextToken"] = token
        page = logs.filter_log_events(**kw)
        for e in page["events"]:
            try:
                payload = json.loads(e["message"])
            except ValueError:
                continue
            rows.append(
                {
                    "event_id": payload.get("eventID"),
                    "event_time": payload.get("eventTime"),
                    "ingest_ms": e["ingestionTime"],
                    "name": payload.get("eventName"),
                    "error": payload.get("errorCode"),
                    "key": (payload.get("userIdentity") or {}).get("accessKeyId"),
                    "identity": (payload.get("userIdentity") or {}).get("userName")
                    or (payload.get("userIdentity") or {}).get("arn"),
                }
            )
        token = page.get("nextToken")
        if not token:
            break
    return rows


def lambda_lines():
    lines = []
    token = None
    while True:
        kw = dict(logGroupName=LAMBDA_GROUP, startTime=int(start.timestamp() * 1000), limit=500)
        if token:
            kw["nextToken"] = token
        page = logs.filter_log_events(**kw)
        for e in page["events"]:
            lines.append({"ts": e["timestamp"], "msg": e["message"].strip()})
        token = page.get("nextToken")
        if not token:
            break
    return lines


events = ct_events()
out["cloudtrail_event_count"] = len(events)
out["cloudtrail_events"] = [
    {
        "time": e["time"],
        "name": e["name"],
        "error": e["raw"].get("errorCode"),
        "key": (e["raw"].get("userIdentity") or {}).get("accessKeyId"),
        "ip": e["raw"].get("sourceIPAddress"),
        "ua": e["raw"].get("userAgent"),
    }
    for e in events
]

log_rows = logs_events()
by_id = {r["event_id"]: r for r in log_rows if r["event_id"]}
lags = []
for e in events:
    r = by_id.get(e["id"])
    if not r or not r.get("event_time"):
        continue
    et = datetime.fromisoformat(r["event_time"].replace("Z", "+00:00"))
    lag = (r["ingest_ms"] / 1000) - et.timestamp()
    lags.append(
        {"name": e["name"], "event_time": r["event_time"], "ingest_utc": datetime.fromtimestamp(r["ingest_ms"] / 1000, timezone.utc).isoformat(), "lag_s": round(lag, 1), "error": r["error"]}
    )
out["cwlogs_lag"] = lags
if lags:
    vals = sorted(x["lag_s"] for x in lags)
    out["cwlogs_lag_summary"] = {
        "n": len(vals),
        "min": vals[0],
        "median": vals[len(vals) // 2],
        "max": vals[-1],
        "mean": round(sum(vals) / len(vals), 1),
    }

lines = lambda_lines()
handled = []
for line in lines:
    if '"alert": "HONEYTOKEN TRIPPED"' in line["msg"] or "HONEYTOKEN TRIPPED" in line["msg"]:
        handled.append({"log_ts": line["ts"], "msg": line["msg"]})
out["lambda_handled"] = handled
out["lambda_line_count"] = len(lines)

alarm = cw.describe_alarm_history(AlarmName=ALARM, HistoryItemType="StateUpdate", StartDate=start, EndDate=now)
out["alarm_history"] = [
    {"time": h["Timestamp"].isoformat(), "summary": h.get("HistorySummary")} for h in alarm["AlarmHistoryItems"]
]

Path("evidence").mkdir(exist_ok=True)
Path("evidence/telemetry.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

print(json.dumps({k: out[k] for k in out if k not in ("cloudtrail_events", "lambda_handled", "cwlogs_lag")}, indent=2))
for row in lags:
    print(f"  {row['event_time']}  {row['name']:<24} lag {row['lag_s']:>6}s  err={row['error']}")
for h in handled:
    print("  LAMBDA", datetime.fromtimestamp(h["log_ts"] / 1000, timezone.utc).isoformat(), h["msg"][:160])
