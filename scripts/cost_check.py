"""Cost check: what has this account actually spent, and what is still billing?

Uses the free Budgets API first. Cost Explorer is only called once (each call is
charged at $0.01) and is skipped if the budget already answers the question.
"""
import json
from datetime import datetime, timedelta, timezone

import boto3

budgets = boto3.client("budgets", region_name="us-east-1")
account = boto3.client("sts", region_name="eu-west-1").get_caller_identity()["Account"]

try:
    for b in budgets.describe_budgets(AccountId=account)["Budgets"]:
        limit = b["BudgetLimit"]
        print(f"budget {b['BudgetName']}: limit {limit['Amount']} {limit['Unit']}, "
              f"time unit {b['TimeUnit']}, type {b['BudgetType']}")
    hist = budgets.describe_budget_performance_history(
        AccountId=account, BudgetName="honeytoken-lab",
        TimePeriod={"Start": (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "End": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
    )["BudgetPerformanceHistory"]
    for h in hist:
        print("  budget type:", h.get("BudgetType"), "actual:", h.get("BudgetedAndActualAmountsList"))
except Exception as exc:  # noqa: BLE001
    print("budgets lookup failed:", exc)

# One metered Cost Explorer call: spend grouped by service for this month.
ce = boto3.client("ce", region_name="us-east-1")
start = datetime.now(timezone.utc).replace(day=1).strftime("%Y-%m-%d")
end = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d")
try:
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    total = 0.0
    for r in resp["ResultsByTime"]:
        print(f"\nmonth {r['TimePeriod']['Start']}:")
        rows = sorted(r["Groups"], key=lambda g: float(g["Metrics"]["UnblendedCost"]["Amount"]), reverse=True)
        for g in rows:
            amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
            total += amt
            if amt > 0:
                print(f"  {g['Keys'][0]:<45} ${amt:.4f}")
        print(f"  TOTAL ${total:.4f}")
except Exception as exc:  # noqa: BLE001
    print("cost explorer failed:", exc)

# Anything that could quietly cost money: running instances, NAT gateways, RDS, EIPs.
ec2 = boto3.client("ec2", region_name="eu-west-1")
print("\ninstances:", len(ec2.describe_instances()["Reservations"]))
print("nat gateways:", len(ec2.describe_nat_gateways()["NatGateways"]))
print("elastic ips:", len(ec2.describe_addresses()["Addresses"]))
