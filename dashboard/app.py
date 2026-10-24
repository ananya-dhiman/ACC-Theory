"""Flask dashboard. Default reads alerts.json; `python dashboard.py --aws` reads the Lambda's CloudWatch logs."""
import json
import sys
from pathlib import Path
from flask import Flask, request, render_template

app = Flask(__name__)
LOG_GROUP = "/aws/lambda/ananya_cloudtrail_threat_detector"
ORDER = {"High": 0, "Medium": 1, "Low": 2}


def load_alerts():
    if "--aws" in sys.argv:
        import boto3
        logs = boto3.client("logs", region_name="ap-south-1")
        out = []
        for e in logs.filter_log_events(logGroupName=LOG_GROUP, filterPattern="ALERT")["events"]:
            try:
                out.append(json.loads(e["message"])["ALERT"])
            except (ValueError, KeyError):
                pass
        return out
    try:
        return json.load(open(Path(__file__).resolve().parent.parent / "output" / "alerts.json"))
    except FileNotFoundError:
        return []


@app.route("/")
def index():
    level = request.args.get("level", "All")
    alerts = sorted(load_alerts(), key=lambda a: (ORDER[a["risk_level"]], a["timestamp"] or ""))
    counts = {l: sum(a["risk_level"] == l for a in alerts) for l in ORDER}
    if level != "All":
        alerts = [a for a in alerts if a["risk_level"] == level]
    return render_template("index.html", alerts=alerts, counts=counts, level=level)


if __name__ == "__main__":
    app.run(debug=True)
