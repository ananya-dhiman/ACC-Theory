# Cloud Security Log Analyzer and Threat Detection System

A serverless prototype that analyses AWS CloudTrail audit events, scores them against custom
Python detection rules, and raises risk-rated alerts. Built with AWS CloudTrail, EventBridge,
Lambda and CloudWatch, plus an optional Flask dashboard.

## Architecture

```
CloudTrail ──► EventBridge rule ──► Lambda (src/lambda_function.py) ──► CloudWatch Logs ──► Flask dashboard
 (records)      (filters events)      (scores each event)               (stores ALERT lines)   (views alerts)
                                              └──► SNS email on High severity (optional)
```

## What it detects and how it scores

| Rule | Points |
|---|---|
| Failed console sign-in | +40 |
| Unauthorized API call (`AccessDenied`, `UnauthorizedOperation`, ...) | +35 |
| Stop logging / delete CloudTrail trail | +60 |
| Access key, login profile, policy attach/put, role trust change | +30 |
| Create/delete user, add user to group | +20 |
| `AdministratorAccess` policy involved | +40 |
| Performed by the root account (added on top) | +30 |

Severity: **Low** 1-29, **Medium** 30-59, **High** 60+. Each alert lists the reasons it fired.
Points stack, so a failed root login scores 70 (High) while the same failure by a normal user scores 40 (Medium).

## Repository layout

```
src/lambda_function.py      detection rules, scoring, Lambda handler (the deployed code)
data/sample_events.json     10 normal/suspicious CloudTrail events with expected severity
demo/demo_batch_event.json  all mock events in one payload for the Lambda Test tab
scripts/replay.py           local evaluation: runs samples, prints PASS/FAIL table
scripts/deploy_aws.py       creates role, Lambda, EventBridge rule, log group (or `update`)
scripts/make_demo_event.py  regenerates demo/demo_batch_event.json from the samples
dashboard/app.py            Flask dashboard (local file or live CloudWatch)
```

## Quick start (no AWS needed)

```bash
pip install -r requirements.txt
python scripts/replay.py          # evaluation table, writes output/alerts.json
python dashboard/app.py           # http://127.0.0.1:5000
```

Expected: `10/10 correct (100%), 8 alerts`.

## Deploy to AWS

1. Provide credentials through your environment or `aws configure`. Never commit keys.
2. Edit `REGION` and the `P` prefix at the top of `scripts/deploy_aws.py` for your account.
3. Run `python scripts/deploy_aws.py`. After code changes, run `python scripts/deploy_aws.py update`.

Resources created (all start with the prefix): IAM role (log-write only), Lambda function,
EventBridge rule, CloudWatch log group (7-day retention). Everything used is within AWS free-tier
allowances; no trail is created, so CloudTrail Event history is the free source.

Note: IAM and console sign-in events are recorded in `us-east-1`. A rule in another region only
sees events from that region, so for a restricted account the demo replays events directly.

## Live demo script

1. **CloudTrail -> Event history** (deployment region): show real recorded events.
2. **Lambda -> your function -> Test tab -> Create new event**, paste the whole contents of
   `demo/demo_batch_event.json`, click **Test**. The result shows `processed: 10, alerts: 8`
   with a level per labelled event. You can also paste a single event from `data/sample_events.json`.
3. **CloudWatch -> Log groups -> `/aws/lambda/<function>`**: the `{"ALERT": ...}` lines appear.
4. **Dashboard with live data** (credentials set in the shell):
   ```bash
   python dashboard/app.py --aws
   ```
   Update `LOG_GROUP` / region at the top of `dashboard/app.py` to match your deployment.
5. **Evaluation**: `python scripts/replay.py` shows the 10-case table.

## Optional: email on High alerts

Create an SNS topic, subscribe an email, set the Lambda env var `SNS_TOPIC_ARN`, and add
`sns:Publish` to the Lambda role.

## Cleanup

Delete the EventBridge rule, Lambda function, IAM role and log group created by the deploy script.
