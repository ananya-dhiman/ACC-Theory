"""CloudTrail threat detector. Runs in AWS Lambda, also importable for local replay."""
import json
import os

IAM_SENSITIVE = {
    "CreateAccessKey": (30, "IAM access key created"),
    "CreateLoginProfile": (30, "Console password created for IAM user"),
    "AttachUserPolicy": (30, "Policy attached to IAM user"),
    "AttachRolePolicy": (30, "Policy attached to IAM role"),
    "PutUserPolicy": (30, "Inline policy added to IAM user"),
    "PutRolePolicy": (30, "Inline policy added to IAM role"),
    "UpdateAssumeRolePolicy": (30, "Role trust policy modified"),
    "CreateUser": (20, "New IAM user created"),
    "DeleteUser": (20, "IAM user deleted"),
    "AddUserToGroup": (20, "User added to IAM group"),
    "StopLogging": (60, "CloudTrail logging stopped"),
    "DeleteTrail": (60, "CloudTrail trail deleted"),
}
UNAUTHORIZED_CODES = ("AccessDenied", "UnauthorizedOperation", "AuthFailure", "UnauthorizedAccess")


def severity(score):
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low" if score > 0 else "None"


def analyze(rec):
    """Return an alert dict for a CloudTrail record, or None if it looks normal."""
    name = rec.get("eventName", "")
    ident = rec.get("userIdentity", {}) or {}
    who = ident.get("arn") or ident.get("userName") or ident.get("type", "unknown")
    score, reasons = 0, []

    if name == "ConsoleLogin" and (rec.get("responseElements") or {}).get("ConsoleLogin") == "Failure":
        score += 40
        reasons.append("Failed console sign-in")

    err = rec.get("errorCode", "")
    if err and any(err.endswith(c) for c in UNAUTHORIZED_CODES):
        score += 35
        reasons.append(f"Unauthorized API call ({err})")

    if name in IAM_SENSITIVE and not err:
        pts, why = IAM_SENSITIVE[name]
        score += pts
        reasons.append(why)
        if "AdministratorAccess" in json.dumps(rec.get("requestParameters") or {}):
            score += 40
            reasons.append("AdministratorAccess policy involved")

    if score and ident.get("type") == "Root":
        score += 30
        reasons.append("Activity by root account")

    if not score:
        return None
    return {
        "timestamp": rec.get("eventTime"),
        "event": name,
        "user": who,
        "source_ip": rec.get("sourceIPAddress"),
        "risk_score": min(score, 100),
        "risk_level": severity(score),
        "reasons": reasons,
    }


def handle(event):
    rec = event.get("detail", event)  # EventBridge wraps the CloudTrail record in "detail"
    alert = analyze(rec)
    if not alert:
        print(json.dumps({"result": "normal", "event": rec.get("eventName")}))
        return {"alert": False, "label": rec.get("_label")}
    if rec.get("_label"):
        alert["label"] = rec["_label"]
    print(json.dumps({"ALERT": alert}))  # lands in CloudWatch Logs
    topic = os.environ.get("SNS_TOPIC_ARN")
    if topic and alert["risk_level"] == "High":
        import boto3
        boto3.client("sns").publish(TopicArn=topic, Subject=f"HIGH alert: {alert['event']}",
                                    Message=json.dumps(alert, indent=2))
    return {"alert": True, **alert}


def lambda_handler(event, context=None):
    if "events" in event:  # demo mode: several mock events in one invocation
        results = [handle(e) for e in event["events"]]
        return {"processed": len(results), "alerts": sum(r["alert"] for r in results),
                "results": [{"label": r.get("label"), "level": r.get("risk_level", "None")} for r in results]}
    return handle(event)
