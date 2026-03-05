import boto3
import json
from datetime import datetime, timedelta, timezone

ec2 = boto3.client("ec2")
cloudtrail = boto3.client("cloudtrail")

LOOKBACK_MINUTES = 10
OWNER_TAG_KEY = "Owner"
SUPPORTED_INSTANCE_CLASSES = ["t3.micro"]


def lambda_handler(event, context):
    events = get_runinstance_events(LOOKBACK_MINUTES)

    for ct_event in events:
        owner = extract_owner(ct_event.get("userIdentity"))
        instance_ids = extract_instance_ids(ct_event)
        if not instance_ids:
            continue
        process_instances(instance_ids, owner)
    return {"status": "complete"}


def get_runinstance_events(lookback_minutes):
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=lookback_minutes)
    paginator = cloudtrail.get_paginator("lookup_events")
    pages = paginator.paginate(
        LookupAttributes=[
            {"AttributeKey": "EventName", "AttributeValue": "RunInstances"}
        ],
        StartTime=start_time,
        EndTime=end_time
    )
    for page in pages:
        for event in page.get("Events", []):
            yield json.loads(event["CloudTrailEvent"])


def extract_owner(user_identity):
    if not user_identity:
        print("User Identity is Unknown")
        return "Unknown"
    if user_identity.get("userName"):
        print("User Identity was obtained from userName")
        return user_identity["userName"]
    if user_identity.get("type") == "AssumedRole":
        print("User Identity was obtained from the AssumedRole")
        return user_identity.get("arn", "").split("/")[-1]
    print("We attempted to fetch userId from the principalId")
    return user_identity.get("principalId", "Unknown")


def extract_instance_ids(ct_event):
    return [
        i["instanceId"]
        for i in ct_event.get("responseElements", {})
        .get("instancesSet", {})
        .get("items", [])
    ]


def process_instances(instance_ids, owner):
    reservations = ec2.describe_instances(
        InstanceIds=instance_ids
    )["Reservations"]
    for reservation in reservations:
        for instance in reservation["Instances"]:
            instance_id = instance["InstanceId"]
            instance_type = instance["InstanceType"]
            existing_tags = {
                t["Key"]: t["Value"]
                for t in instance.get("Tags", [])
            }
            if OWNER_TAG_KEY not in existing_tags:
                ec2.create_tags(
                    Resources=[instance_id],
                    Tags=[{"Key": OWNER_TAG_KEY, "Value": owner}]
                )
                print(f"Tagged {instance_id} with {OWNER_TAG_KEY}={owner}")
            # Enforce Instance Type Policy
            # 
            # if instance_type not in SUPPORTED_INSTANCE_CLASSES:
            #     print(
            #         f"{instance_id} is type {instance_type} "
            #         f"(not in {SUPPORTED_INSTANCE_CLASSES})"
            #     )
            #     ec2.stop_instances(InstanceIds=[instance_id])
            #     print(f"Stopped unsupported instance {instance_id}")
