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
        self.assertIn("const identity=JSON.stringify([st,st==='BLOCKED_HUMAN'?String(g?.id||''):'',JSON.stringify(g?.self_hosting_candidate?.paths||[])]);", source)
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

    def test_self_hosting_submission_narrows_to_displayed_paths_and_retains_feedback(self):
        submission = re.search(r"async function submitSelfHosting\(\)\{(.*?)\nasync function logout", self.page, re.DOTALL)
        self.assertIsNotNone(submission)
        source = submission.group(1)

        self.assertIn("const authority=latestSnapshot?.gate?.authority_block", source)
        self.assertIn("filter(path=>allowed.has(path))", source)
        self.assertIn("paths.length!==context.paths.length", source)
        self.assertIn("if(button)button.disabled=true;try", source)
        self.assertIn("finally{if(button)button.disabled=false;}", source)
        self.assertIn("renderActionResult('authorize_self_hosting',j,context.paths);await refresh();", source)
        self.assertIn("catch(e){renderActionFailure('authorize_self_hosting',e.message);}", source)
        self.assertIn("function renderActionFailure(action,message){actionFeedback={action,error:message||'action failed'}", self.page)
        self.assertIn("actionFeedback={action,stdout:j.stdout,stderr:j.stderr,grantedPaths};renderActionFeedback();", self.page)
        self.assertIn("Granted authority over named RALPH tooling paths:\\n${feedback.grantedPaths.join('\\n')}", self.page)
        self.assertIn("renderSelfHostingReview();renderActionFeedback();renderHTML('error','')", self.page)

    def test_unchanged_read_only_output_avoids_rewrites_and_event_scroll(self):
        self.assertIn("if(values.get(kind)===next)", self.page)
        self.assertIn("return false;", self.page)
        self.assertIn("renderText('report',s.report?.preview||'No completion report yet.')", self.page)
        self.assertIn("renderText('log',(s.live_log||[]).join('\\n')||'No output yet.')", self.page)
        self.assertIn("if(renderHTML('events',events))document.getElementById('events').scrollTop", self.page)

    def test_operator_actions_publish_transient_state_before_waiting_for_controller(self):
        self.assertIn("function actionState(action)", self.page)
        self.assertIn("showActionState(action);const j=await post(p)", self.page)
        self.assertIn("localActionState||c.status", self.page)
        self.assertIn("QUALIFYING", self.page)
        self.assertIn("REVIEWING", self.page)
        self.assertIn("COMMITTING", self.page)
        self.assertIn("PUSHING", self.page)

    def test_usage_layout_is_compact_and_plan_comments_expand_in_place(self):
        self.assertIn("usage-grid{display:grid;grid-template-columns:repeat(6", self.page)
        self.assertIn("wins.slice(0,2)", self.page)
        self.assertIn('<details class="plan-comment">', self.page)
        self.assertIn('class="plan-comment-body"', self.page)
        self.assertIn("max-height:90px;overflow:auto", self.page)

    def test_polling_interval_and_csrf_action_path_remain_stable(self):
        self.assertIn("refresh();setInterval(refresh,1500);", self.page)
        self.assertIn(
            "fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-RALPH-CSRF':CSRF}",
            self.page,
        )
        self.assertIn("if self.headers.get(\"X-RALPH-CSRF\") != self.server.csrf_token", MODULE_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
