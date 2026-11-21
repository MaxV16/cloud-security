# Serverless Honeytokens in AWS

Coursework for Network and System Security (SETU, Semester 1 2026/27).

**Title:** Serverless Honeytokens in AWS: A Comparative Evaluation of Event-Driven and
Log-Based Detection for Cloud Credential Misuse

Maksim Karakulin (20106742), William Nolan (20107153).

## What the lab does

The lab is a three-layer decoy environment in AWS account 508261694250, region `eu-west-1`.
Everything in it is serverless or free tier, and the whole build cost under a euro for the month.

- **Deception**: an IAM user `canary-backup-admin` with a `deny-all` inline policy and one
  access key, an S3 bucket `prod-backup-credentials-2026-508261694250` holding a fake
  `credentials.txt` and an encrypted "database dump", and a Secrets Manager secret
  `prod/db/master-password`. None of them is used by anything legitimate, so any call made
  with the canary credentials is an alert.
- **Telemetry**: a multi-region CloudTrail trail `honeytoken-trail` with log file validation,
  management events and S3 data events scoped to the honey bucket, delivered to CloudWatch Logs
  in `/aws/cloudtrail/honeytoken`.
- **Detection**: two paths that read the same trail.
  - Path A: EventBridge rules `honeytoken-canary-key` and `honeytoken-honey-bucket` to a Lambda
    function to SNS.
  - Path B: CloudWatch Logs metric filter `CanaryAccessKeyUse` to a 60 second alarm to SNS.
- **Response**: the Lambda function sets the canary key to `Inactive` and publishes the event
  details (API called, source IP, region, timestamp) to the alert topic.

## Layout

```
infra/        deploy.py - idempotent deployment in four stages
lambda/       killswitch/handler.py - the responder
scripts/      attack simulation, latency trials, artefact dump, CSPM helpers
evidence/     trials.json, artefacts.json, cspm.json, prowler scans, console screenshots
```

## Rebuilding the lab

```
python infra/deploy.py guardrails
python infra/deploy.py deception
python infra/deploy.py detection
python infra/deploy.py response
```

Each stage is idempotent, so it can be re-run to repair a partially deployed stack. The canary
key and secret are written to `.canary/credentials`, which is gitignored.

## Measuring the two paths

```
python scripts/simulate_attack.py     # fire the decoys once, end to end
python scripts/run_trials.py          # four timed trials, writes evidence/trials.json
python scripts/dump_artefacts.py      # snapshot the deployed configuration
```

`run_trials.py` re-arms the canary key before each trial, makes one real API call with it, and
times both detection paths from the timestamp inside the CloudTrail record rather than from the
local clock. `evidence/trials.json` is the raw output of those runs.

## CSPM scans

```
python -m prowler aws --profile default --region eu-west-1 \
  --output-formats csv json-ocsf --output-directory evidence/prowler/before \
  --service iam s3 cloudtrail cloudwatch awslambda sns eventbridge secretsmanager ec2 guardduty
```

The `before` and `after` directories hold the two scans, taken before and after four cheap
hardening changes (IAM password policy, account-level S3 public access block, GuardDuty, EBS
default encryption). `scripts/cspm_diff.py` works out which checks changed between them.

## Note on the account

The lab ran in a personal AWS account and has since been torn down with `scripts/teardown.py`.
The evidence files and screenshots in this repository are the record of the runs; the deployment
can be recreated from `infra/deploy.py` if it is ever needed again.
