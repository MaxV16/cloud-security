"""
Honeytoken kill switch.

Triggered by EventBridge when the canary IAM access key is used, or when any
principal touches the honey S3 bucket.  The function records what happened,
deactivates the canary key so it cannot be used again, and publishes a
human-readable alert to SNS.

Nothing in here is generic IAM administration: the execution role can only
call iam:UpdateAccessKey / iam:ListAccessKeys on the single canary user, which
keeps the blast radius of a compromised Lambda at zero.
"""

import json
import os

import boto3

iam = boto3.client("iam")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
CANARY_USER = os.environ.get("CANARY_USER", "canary-backup-admin")


def lambda_handler(event, context):
    detail = event.get("detail", {})
    identity = detail.get("userIdentity", {}) or {}
    access_key = identity.get("accessKeyId", "unknown")
    event_name = detail.get("eventName", "unknown")
    event_time = detail.get("eventTime", "unknown")
    source_ip = detail.get("sourceIPAddress", "unknown")
    agent = detail.get("userAgent", "unknown")
    region = detail.get("awsRegion", "unknown")
    error = (detail.get("errorCode") or "none")

    action = "no action taken"
    key_was_active = False

    # Only deactivate a key that is actually on the canary user.  The event
    # pattern should already guarantee this, but defence in depth is cheap.
    try:
        keys = iam.list_access_keys(UserName=CANARY_USER)["AccessKeyMetadata"]
        for key in keys:
            if key["AccessKeyId"] == access_key and key["Status"] == "Active":
                iam.update_access_key(
                    UserName=CANARY_USER, AccessKeyId=access_key, Status="Inactive"
                )
                key_was_active = True
                action = f"access key {access_key} set to Inactive"
    except Exception as exc:  # noqa: BLE001 - the alert matters more than the traceback
        action = f"deactivation failed: {exc}"

    message = {
        "alert": "HONEYTOKEN TRIPPED",
        "detected_at": event_time,
        "api_called": event_name,
        "canary_access_key": access_key,
        "source_ip": source_ip,
        "user_agent": agent,
        "region": region,
        "api_error": error,
        "response": action,
        "key_was_active": key_was_active,
    }

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject="[HONEYTOKEN] Canary AWS key used - key deactivated",
        Message=json.dumps(message, indent=2),
    )

    print(json.dumps({"message": "handled", **message}))
    return {"statusCode": 200, "body": message}
