from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph_web.py"
spec = importlib.util.spec_from_file_location("ralph_web_live_refresh_module", MODULE_PATH)
web = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = web
spec.loader.exec_module(web)


class LiveRefreshContractTests(unittest.TestCase):
    def setUp(self):
        self.page = web.PAGE

    def test_controls_preserve_drafts_for_same_identity_and_replace_on_transition(self):
        controls = re.search(r"function renderControls\(s\)\{(.*?)\nfunction renderUsage", self.page, re.DOTALL)
        self.assertIsNotNone(controls)
        source = controls.group(1)

        self.assertIn('id="goalInput"', source)
        self.assertIn('id="steerInput"', source)
        self.assertIn("const identity=JSON.stringify([st,st==='BLOCKED_HUMAN'?String(g?.id||''):'']);", source)
        self.assertIn("if(identity===renderedControlsIdentity)return;", source)
        self.assertLess(
            source.index("if(identity===renderedControlsIdentity)return;"),
            source.index("renderHTML('controls',out)"),
        )
        self.assertIn("renderedControlsIdentity=identity;", source)

    def test_selection_intersection_defers_and_flushes_the_latest_update(self):
        self.assertIn("function selectionIntersectsTarget(target)", self.page)
        self.assertIn("selection.getRangeAt(i).intersectsNode(target)", self.page)
        self.assertIn("if(selectionIntersectsTarget(target)){pendingFor(target).set(kind,{value:next,write});return false;}", self.page)
        self.assertIn("const renderedValues=new WeakMap(),pendingTargetUpdates=new Map()", self.page)
        self.assertIn("for(const [kind,update] of updates)renderValue(target,kind,update.value,update.write);", self.page)
        self.assertIn("document.addEventListener('selectionchange',flushPendingTargetUpdates);", self.page)

    def test_unchanged_read_only_output_avoids_rewrites_and_event_scroll(self):
        self.assertIn("if(values.get(kind)===next)", self.page)
        self.assertIn("return false;", self.page)
        self.assertIn("renderText('report',s.report?.preview||'No completion report yet.')", self.page)
        self.assertIn("renderText('log',(s.live_log||[]).join('\\n')||'No output yet.')", self.page)
        self.assertIn("if(renderHTML('events',events))document.getElementById('events').scrollTop", self.page)

    def test_polling_interval_and_csrf_action_path_remain_stable(self):
        self.assertIn("refresh();setInterval(refresh,1500);", self.page)
        self.assertIn(
            "fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-RALPH-CSRF':CSRF}",
            self.page,
        )
        self.assertIn("if self.headers.get(\"X-RALPH-CSRF\") != self.server.csrf_token", MODULE_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
