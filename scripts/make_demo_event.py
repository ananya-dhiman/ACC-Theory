"""Build demo/demo_batch_event.json (all mock events in one Lambda Test payload) from data/sample_events.json."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
cases = json.loads((ROOT / "data" / "sample_events.json").read_text())
batch = {"events": [{"_label": c["name"], **c["event"]} for c in cases]}
(ROOT / "demo" / "demo_batch_event.json").write_text(json.dumps(batch, indent=2))
print("wrote demo/demo_batch_event.json with", len(batch["events"]), "events")
