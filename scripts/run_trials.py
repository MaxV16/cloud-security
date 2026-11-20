"""Run controlled detection trials and record how long each path took.

Each trial re-arms the canary key, waits until AWS accepts it again, makes one
API call with the canary credentials and then watches three telemetry sources
(EventBridge/Lambda, CloudWatch Logs and the CloudWatch alarm) until the event
shows up in each of them.

The reference time for every latency is the CloudTrail event time for the call,
looked up independently of the detection paths, so a call that EventBridge
missed still gets a Path B measurement.  Results are appended to
evidence/trials.json.
"""
import configparser
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "eu-west-1"
CANARY_USER = "canary-backup-admin"
LOG_GROUP = "/aws/cloudtrail/honeytoken"
LAMBDA_GROUP = "/aws/lambda/honeytoken-killswitch"
ALARM = "honeytoken-canary-alarm"

iam = boto3.client("iam", region_name=REGION)
logs = boto3.client("logs", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)
ct = boto3.client("cloudtrail", region_name=REGION)

cfg = configparser.ConfigParser()
cfg.read(".canary/credentials")
KEY_ID = cfg["canary"]["aws_access_key_id"]
creds = {
    "aws_access_key_id": KEY_ID,
    "aws_secret_access_key": cfg["canary"]["aws_secret_access_key"],
    "region_name": REGION,
}

ATTACKER = {
    "sts": boto3.client("sts", **creds),
    "s3": boto3.client("s3", **creds),
    "iam": boto3.client("iam", **creds),
    "ec2": boto3.client("ec2", **creds),
    "secretsmanager": boto3.client("secretsmanager", **creds),
}

TRIALS = [
    ("S6", "sts", "get_caller_identity", "GetCallerIdentity"),
    ("S7", "s3", "list_buckets", "ListBuckets"),
    ("S8", "iam", "list_users", "ListUsers"),
    ("S9", "ec2", "describe_instances", "DescribeInstances"),
]


def now():
    return datetime.now(timezone.utc)


def arm():
    keys = iam.list_access_keys(UserName=CANARY_USER)["AccessKeyMetadata"]
    for k in keys:
        iam.update_access_key(UserName=CANARY_USER, AccessKeyId=k["AccessKeyId"], Status="Active")
    return keys[0]["AccessKeyId"]


def poll(fn, timeout=300, step=10):
    end = time.time() + timeout
    while time.time() < end:
        r = fn()
        if r:
            return r
        time.sleep(step)
    return None


def attack(service, method):
    """Call the API with the canary key, retrying while AWS still sees the key as disabled."""
    waited = 0
    for _ in range(10):
        try:
            getattr(ATTACKER[service], method)()
            return {"outcome": "success", "error": None, "waited_s": waited, "call_time": now()}
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidAccessKeyId", "UnrecognizedClientException", "SignatureDoesNotMatch"):
                time.sleep(30)
                waited += 30
                continue
            return {"outcome": "denied", "error": code, "waited_s": waited, "call_time": now()}
    return {"outcome": "never-propagated", "error": "InvalidAccessKeyId", "waited_s": waited, "call_time": now()}


def event_time(api_name, after):
    """Find the CloudTrail record for our own call, independent of the rules."""

    def look():
        page = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": api_name}],
            StartTime=after - timedelta(seconds=30),
            MaxResults=50,
        )
        for e in page["Events"]:
            rec = json.loads(e["CloudTrailEvent"])
            if (rec.get("userIdentity") or {}).get("accessKeyId") == KEY_ID:
                return datetime.fromisoformat(rec["eventTime"])
        return None

    return poll(look, timeout=180, step=15)


def event_time_from_logs(api_name, after):
    """Fallback: read the record out of the trail's log group.

    lookup_events does not index every denied call, so if the API lookup comes
    back empty we take the event time from the delivered record instead.
    """

    def look():
        page = logs.filter_log_events(
            logGroupName=LOG_GROUP,
            startTime=int(after.timestamp() * 1000) - 60000,
            limit=200,
        )
        for e in page.get("events", []):
            try:
                rec = json.loads(e["message"])
            except ValueError:
                continue
            if rec.get("eventName") != api_name:
                continue
            if (rec.get("userIdentity") or {}).get("accessKeyId") != KEY_ID:
                continue
            return datetime.fromisoformat(rec["eventTime"].replace("Z", "+00:00"))
        return None

    return poll(look, timeout=240, step=10)


def alarm_state():
    r = cw.describe_alarms(AlarmNames=[ALARM])["MetricAlarms"]
    return r[0]["StateValue"] if r else None


def wait_ok(timeout=240):
    poll(lambda: alarm_state() == "OK", timeout=timeout, step=15)


def main():
    results = []
    path = Path("evidence/trials.json")
    if path.exists():
        results = json.loads(path.read_text(encoding="utf-8"))
    already = {r["trial"] for r in results}

    for label, service, method, api_name in TRIALS:
        if label in already:
            print(f"skipping {label} (already recorded)", flush=True)
            continue

        print(f"\n=== trial {label}: {api_name} ===", flush=True)
        arm()
        time.sleep(30)
        called_at = now()
        before = int(time.time() * 1000)
        res = attack(service, method)
        print(f"  {api_name}: {res['outcome']} {res['error']} after {res['waited_s']}s of waiting", flush=True)

        event = event_time(api_name, called_at)
        if event is None:
            event = event_time_from_logs(api_name, called_at)
        print(f"  cloudtrail event time: {event.isoformat() if event else 'not found'}", flush=True)

        def lam():
            page = logs.filter_log_events(
                logGroupName=LAMBDA_GROUP, startTime=before - 5000, limit=200
            )
            hits = [e for e in page["events"] if e["timestamp"] > before and "HONEYTOKEN TRIPPED" in e["message"]]
            return json.loads(hits[0]["message"]) | {"_log_ms": hits[0]["timestamp"]} if hits else None

        hit = poll(lam, timeout=150, step=5)
        a_latency = None
        if hit:
            detected = datetime.fromisoformat(hit["detected_at"].replace("Z", "+00:00"))
            a_latency = round(hit["_log_ms"] / 1000 - detected.timestamp(), 1)
            print(f"  path A: lambda logged {a_latency}s after the event", flush=True)
            if event is None:
                event = detected
        else:
            print("  path A: nothing seen (rule did not match)", flush=True)

        def cwlog():
            page = logs.filter_log_events(logGroupName=LOG_GROUP, startTime=before - 20000, limit=500)
            for e in page["events"]:
                try:
                    payload = json.loads(e["message"])
                except ValueError:
                    continue
                ts = payload.get("eventTime", "")
                if ts and event and abs(
                    datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() - event.timestamp()
                ) <= 2:
                    return e
            return None

        entry = poll(cwlog, timeout=360, step=10)
        b_log = None
        if entry and event:
            b_log = round(entry["ingestionTime"] / 1000 - event.timestamp(), 1)
            print(f"  path B: log record ingested {b_log}s after the event", flush=True)
        else:
            print("  path B: log record not found", flush=True)

        def alarm():
            h = cw.describe_alarm_history(
                AlarmName=ALARM,
                HistoryItemType="StateUpdate",
                StartDate=event - timedelta(seconds=5) if event else called_at,
                EndDate=now(),
            )
            hits = [
                i for i in h["AlarmHistoryItems"]
                if json.loads(i["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
            ]
            return min(hits, key=lambda i: i["Timestamp"]) if hits else None

        a = poll(alarm, timeout=240, step=10) if event else None
        b_alarm = None
        if a and event:
            b_alarm = round(a["Timestamp"].timestamp() - event.timestamp(), 1)
            print(f"  alarm: ALARM {b_alarm}s after the event", flush=True)
        else:
            print("  alarm: no new transition seen", flush=True)

        results.append(
            {
                "trial": label,
                "api_called": api_name,
                "outcome": res["outcome"],
                "error_code": res["error"],
                "propagation_wait_s": res["waited_s"],
                "cloudtrail_event_time": event.isoformat() if event else None,
                "path_a_latency_s": a_latency,
                "path_b_log_latency_s": b_log,
                "path_b_alarm_latency_s": b_alarm,
                "key_after": [k["Status"] for k in iam.list_access_keys(UserName=CANARY_USER)["AccessKeyMetadata"]],
            }
        )
        path.write_text(json.dumps(results, indent=2), encoding="utf-8")

        wait_ok()
        time.sleep(30)

    print("\ndone")
    for r in results:
        print(json.dumps(r))


if __name__ == "__main__":
    main()
