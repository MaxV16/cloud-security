#!/usr/bin/env python3
"""
Controlled misuse of the honeytoken and measurement of both detection paths.

Phase 1 runs the attack sequence with the leaked canary key, re-arming the key
between steps (the kill switch disables it after the first use, which is the
point).  Phase 2 correlates every step with:

  * the CloudTrail event (lookup-events)
  * the CloudWatch Logs copy of that event (ingestion time)
  * the EventBridge -> Lambda invocation (Lambda log timestamp)
  * the CloudWatch alarm state change (alarm history)

Everything lands in evidence/attack_results.json.
"""

import datetime as dt
import json
import os
import pathlib
import subprocess
import time

import boto3

REGION = "eu-west-1"
ACCOUNT = "508261694250"
CANARY_USER = "canary-backup-admin"
CANARY_KEY = "AKIAXMVWB7MVLTPKSPCX"
HONEY_BUCKET = f"prod-backup-credentials-2026-{ACCOUNT}"
LOG_GROUP = "/aws/cloudtrail/honeytoken"
LAMBDA_LOG_GROUP = "/aws/lambda/honeytoken-killswitch"
ALARM = "honeytoken-canary-alarm"

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"
EVIDENCE.mkdir(exist_ok=True)

iam = boto3.client("iam")
ct = boto3.client("cloudtrail", region_name=REGION)
logs = boto3.client("logs", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def canary_env():
    values = {}
    for line in (ROOT / ".canary" / "credentials").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()
    env = dict(os.environ)
    env.pop("AWS_PROFILE", None)
    env["AWS_ACCESS_KEY_ID"] = values["aws_access_key_id"]
    env["AWS_SECRET_ACCESS_KEY"] = values["aws_secret_access_key"]
    env["AWS_DEFAULT_REGION"] = REGION
    return env


def run(cmd, use_canary=True):
    started = utcnow()
    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        env=canary_env() if use_canary else os.environ,
      )
    finished = utcnow()
    return {
        "command": cmd,
        "started": started.isoformat(),
        "finished": finished.isoformat(),
        "exit_code": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def rearm():
    iam.update_access_key(UserName=CANARY_USER, AccessKeyId=CANARY_KEY, Status="Active")


def key_status():
    for k in iam.list_access_keys(UserName=CANARY_USER)["AccessKeyMetadata"]:
        if k["AccessKeyId"] == CANARY_KEY:
            return k["Status"]
    return "MISSING"


def wait_for(fn, timeout=900, interval=10):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    return last


# --------------------------------------------------------------------------
# phase 2 lookups
# --------------------------------------------------------------------------
def find_cloudtrail_event(step, timeout=900):
    start = dt.datetime.fromisoformat(step["started"]) - dt.timedelta(seconds=30)
    end = dt.datetime.fromisoformat(step["finished"]) + dt.timedelta(seconds=600)

    def probe():
        resp = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": step["event_name"]}],
            StartTime=start,
            EndTime=end,
            MaxResults=50,
        )
        for e in resp["Events"]:
            detail = json.loads(e["CloudTrailEvent"])
            if detail.get("userIdentity", {}).get("accessKeyId") == CANARY_KEY:
                return {
                    "event_time": e["EventTime"].isoformat(),
                    "event_id": e["EventId"],
                    "event_name": detail.get("eventName"),
                    "error_code": detail.get("errorCode"),
                    "error_message": detail.get("errorMessage"),
                    "source_ip": detail.get("sourceIPAddress"),
                    "user_agent": detail.get("userAgent"),
                    "read_only": detail.get("readOnly"),
                    "event_source": detail.get("eventSource"),
                    "raw": detail,
                }
        return None

    return wait_for(probe, timeout=timeout, interval=15)


def find_cwlogs_event(step, timeout=1200):
    start_ms = int((dt.datetime.fromisoformat(step["started"]) - dt.timedelta(minutes=2)).timestamp() * 1000)
    end_ms = int((dt.datetime.fromisoformat(step["finished"]) + dt.timedelta(minutes=30)).timestamp() * 1000)

    def probe():
        resp = logs.filter_log_events(
            logGroupName=LOG_GROUP,
            startTime=start_ms,
            endTime=end_ms,
            filterPattern='{ ($.userIdentity.accessKeyId = "%s") }' % CANARY_KEY,
            limit=100,
        )
        for e in resp["events"]:
            d = json.loads(e["message"])
            if d.get("eventName") == step["event_name"]:
                return {
                    "log_event_timestamp": dt.datetime.fromtimestamp(
                        e["timestamp"] / 1000, dt.timezone.utc
                    ).isoformat(),
                    "ingestion_time": dt.datetime.fromtimestamp(
                        e["ingestionTime"] / 1000, dt.timezone.utc
                    ).isoformat(),
                    "event_id": d.get("eventID"),
                }
        return None

    return wait_for(probe, timeout=timeout, interval=15)


def find_lambda_invocation(step, timeout=600):
    start_ms = int((dt.datetime.fromisoformat(step["started"]) - dt.timedelta(minutes=1)).timestamp() * 1000)
    end_ms = int((dt.datetime.fromisoformat(step["finished"]) + dt.timedelta(minutes=15)).timestamp() * 1000)
    pattern = '{ $.api_called = "%s" }' % step["event_name"]

    def probe():
        resp = logs.filter_log_events(
            logGroupName=LAMBDA_LOG_GROUP,
            startTime=start_ms,
            endTime=end_ms,
            filterPattern=pattern,
            limit=50,
        )
        for e in resp["events"]:
            return {
                "log_timestamp": dt.datetime.fromtimestamp(
                    e["timestamp"] / 1000, dt.timezone.utc
                ).isoformat(),
                "message": e["message"].strip(),
            }
        return None

    return wait_for(probe, timeout=timeout, interval=10)


def find_alarm_state(step, timeout=1200):
    start = dt.datetime.fromisoformat(step["started"]) - dt.timedelta(minutes=1)

    def probe():
        resp = cw.describe_alarm_history(
            AlarmName=ALARM,
            HistoryItemType="StateUpdate",
            StartDate=start,
            EndDate=utcnow() + dt.timedelta(minutes=5),
            MaxRecords=50,
        )
        for item in resp["AlarmHistoryItems"]:
            data = json.loads(item["HistoryData"])
            if data.get("newState", {}).get("stateValue") == "ALARM":
                return {
                    "timestamp": item["Timestamp"].isoformat(),
                    "summary": item["HistorySummary"],
                }
        return None

    return wait_for(probe, timeout=timeout, interval=15)


def seconds_between(a, b):
    return round((dt.datetime.fromisoformat(b) - dt.datetime.fromisoformat(a)).total_seconds(), 1)


# --------------------------------------------------------------------------
def main():
    steps = [
        ("S1", "GetCallerIdentity", f"aws sts get-caller-identity", True),
        ("S2", "ListBucket", f"aws s3 ls s3://{HONEY_BUCKET}", True),
        ("S3", "GetObject", f"aws s3 cp s3://{HONEY_BUCKET}/backup/credentials.txt -", True),
        (
            "S4",
            "GetSecretValue",
            "aws secretsmanager get-secret-value --secret-id prod/db/master-password",
            True,
        ),
        ("S5", "ListBucket", f"aws s3 ls s3://{HONEY_BUCKET} --profile default", False),
    ]

    results = []
    for tag, event_name, command, use_canary in steps:
        print(f"\n=== {tag} {event_name} ({'canary key' if use_canary else 'admin principal'}) ===")
        if use_canary:
            rearm()
            print(f"key re-armed, status={key_status()}")
        step = {"tag": tag, "event_name": event_name, "actor": "canary" if use_canary else "admin"}
        step.update(run(command, use_canary=use_canary))
        print(f"exit={step['exit_code']}  stderr={step['stderr'][:200]}")
        if use_canary:
            wait_for(lambda: key_status() == "Inactive", timeout=120, interval=5)
            print(f"key status after step: {key_status()}")
            step["key_status_after"] = key_status()
        results.append(step)
        time.sleep(10)

    print("\n=== phase 2: correlating telemetry ===")
    for step in results:
        print(f"  correlating {step['tag']} ...", flush=True)
        step["cloudtrail"] = find_cloudtrail_event(step)
        step["cloudwatch_logs"] = find_cwlogs_event(step)
        step["lambda"] = find_lambda_invocation(step)
        step["alarm"] = find_alarm_state(step)

        if step.get("cloudtrail"):
            step["event_time"] = step["cloudtrail"]["event_time"]
            if step.get("lambda"):
                step["eventbridge_detection_s"] = seconds_between(
                    step["event_time"], step["lambda"]["log_timestamp"]
                )
            if step.get("cloudwatch_logs"):
                step["cwlogs_delivery_s"] = seconds_between(
                    step["event_time"], step["cloudwatch_logs"]["ingestion_time"]
                )
            if step.get("alarm"):
                step["alarm_latency_s"] = seconds_between(step["event_time"], step["alarm"]["timestamp"])

    (EVIDENCE / "attack_results.json").write_text(json.dumps(results, indent=2))
    print(f"\nwritten to {EVIDENCE / 'attack_results.json'}")


if __name__ == "__main__":
    main()
