"""Recompute Path B alarm latencies from the real alarm history.

The first version of run_trials.py read the most recent ALARM entry in
describe_alarm_history(), which is wrong once the alarm has already been in
ALARM earlier in the run: it returns a timestamp from before the trial.  This
script takes every ALARM transition recorded for the alarm and picks the first
one that is at or after the CloudTrail event time of each trial.

    python scripts/fix_alarm_latency.py
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent.parent
TRIALS = ROOT / "evidence" / "trials.json"
ALARM = "honeytoken-canary-alarm"
REGION = "eu-west-1"


def parse(ts):
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc)
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(timezone.utc)


def main():
    cw = boto3.client("cloudwatch", region_name=REGION)
    history = cw.describe_alarm_history(
        AlarmName=ALARM, HistoryItemType="StateUpdate", MaxRecords=100
    )["AlarmHistoryItems"]

    alarms = []
    for item in history:
        data = json.loads(item["HistoryData"])
        if data.get("newState", {}).get("stateValue") == "ALARM":
            alarms.append(parse(item["Timestamp"]))
    alarms.sort()
    print("ALARM transitions:", [a.isoformat() for a in alarms])

    trials = json.loads(TRIALS.read_text(encoding="utf-8"))
    for t in trials:
        if not t.get("cloudtrail_event_time"):
            continue
        event = parse(t["cloudtrail_event_time"])
        later = [a for a in alarms if a >= event]
        if later:
            t["path_b_alarm_latency_s"] = round((later[0] - event).total_seconds(), 1)
        else:
            t["path_b_alarm_latency_s"] = None
        print(t["trial"], t["api_called"], "->", t["path_b_alarm_latency_s"])

    TRIALS.write_text(json.dumps(trials, indent=2), encoding="utf-8")
    print("updated", TRIALS)


if __name__ == "__main__":
    main()
