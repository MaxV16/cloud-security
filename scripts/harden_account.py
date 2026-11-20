"""Apply a small set of free or trial-tier account hardening changes.

These are the changes that the before/after CSPM comparison in Section 4.2 is
built on.  Nothing here touches the honeytoken resources themselves; the point
is to show what a CSPM tool reports for a fresh student account and how much of
that can be fixed without spending money.

    python scripts/harden_account.py
"""

import boto3

REGION = "eu-west-1"
ACCOUNT = "508261694250"


def password_policy():
    iam = boto3.client("iam")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=365,
        PasswordReusePrevention=24,
        HardExpiry=False,
    )
    print("password policy: 14 chars, complexity on, reuse 24, max age 365")


def s3_account_block():
    s3control = boto3.client("s3control", region_name=REGION)
    s3control.put_public_access_block(
        AccountId=ACCOUNT,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print("s3: account-level public access block enabled")


def guardduty():
    gd = boto3.client("guardduty", region_name=REGION)
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        print("guardduty: detector already present", existing[0])
        return
    detector = gd.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES")[
        "DetectorId"
    ]
    print("guardduty: created detector", detector)


def ebs_encryption():
    ec2 = boto3.client("ec2", region_name=REGION)
    ec2.enable_ebs_encryption_by_default()
    ec2.modify_ebs_default_kms_key_id(KmsKeyId="alias/aws/ebs")
    print("ec2: EBS default encryption on (aws/ebs key)")


if __name__ == "__main__":
    password_policy()
    s3_account_block()
    guardduty()
    ebs_encryption()
