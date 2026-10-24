"""Replay sample events through the detector, print a results table, save output/alerts.json."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lambda_function import analyze  # noqa: E402

cases = json.loads((ROOT / "data" / "sample_events.json").read_text())
alerts, correct = [], 0
print(f"{'TEST CASE':28}{'EXPECTED':10}{'GOT':8}{'SCORE':6} RESULT")
for c in cases:
    a = analyze(c["event"])
    got = a["risk_level"] if a else "None"
    ok = got == c["expected"]
    correct += ok
    if a:
        alerts.append(a)
    score = a["risk_score"] if a else 0
    print(f"{c['name']:28}{c['expected']:10}{got:8}{score:<6} {'PASS' if ok else 'FAIL'}")
(ROOT / "output").mkdir(exist_ok=True)
(ROOT / "output" / "alerts.json").write_text(json.dumps(alerts, indent=2))
print(f"\n{correct}/{len(cases)} correct ({100 * correct // len(cases)}%), {len(alerts)} alerts -> output/alerts.json")
