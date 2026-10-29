"""Oudere workflowbestanden (push, schedule) mogen niet meer vanzelf scannen."""
import importlib.util, os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def laad(env):
    for k in ("GITHUB_EVENT_NAME", "CM_AUTOMATISCH", "GITHUB_STEP_SUMMARY", "CM_GEBEURTENIS"):
        os.environ.pop(k, None)
    os.environ.update(env)
    spec = importlib.util.spec_from_file_location("scan_ci", ROOT / "action" / "scan_ci.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
som = Path(tempfile.mkdtemp()) / "som.md"
for ev in ("push", "schedule", "pull_request"):
    m = laad({"GITHUB_EVENT_NAME": ev, "GITHUB_STEP_SUMMARY": str(som)})
    assert m.alleen_handmatig() is True, ev
    assert m.main() == 0, ev
assert "niet uitgevoerd" in som.read_text()
assert laad({"GITHUB_EVENT_NAME": "workflow_dispatch"}).alleen_handmatig() is False
assert laad({"GITHUB_EVENT_NAME": "push", "CM_AUTOMATISCH": "ja"}).alleen_handmatig() is False
for ev in ("push", "merge_request_event", "schedule", "IndividualCI", "BatchedCI", "PullRequest"):
    assert laad({"CM_GEBEURTENIS": ev, "GITHUB_STEP_SUMMARY": str(som)}).alleen_handmatig() is True, ev
for ev in ("web", "custom", "Manual"):
    assert laad({"CM_GEBEURTENIS": ev}).alleen_handmatig() is False, ev
print("ok: alleen handmatig")
