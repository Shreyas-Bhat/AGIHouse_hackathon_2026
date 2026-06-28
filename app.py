"""
Streamlit demo — multi-agent identity & access control.
Run with: streamlit run app.py
"""
from dotenv import load_dotenv
load_dotenv()

import os
import time
import threading
import pandas as pd
import streamlit as st

from multi_agent import (
    AgentForest, generate_plan, TASK,
    run_passthrough, run_easy, run_medium, run_hard,
    run_resolve, run_investigation, run_timeout,
)

os.makedirs("audits", exist_ok=True)

st.set_page_config(page_title="Secure Delegate Demo", layout="wide", page_icon="🔐")

st.markdown("""
<style>
[data-testid="stSidebar"] .stButton { margin-top: -0.5rem; margin-bottom: -0.5rem; }
[data-testid="stSidebar"] hr { margin-top: 0.4rem; margin-bottom: 0.4rem; }
[data-testid="stSidebar"] h1 { margin-bottom: 0; padding-bottom: 0; }
[data-testid="stSidebar"] .stCaption { margin-top: 0; }
</style>
""", unsafe_allow_html=True)

# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS = {
    "⚡ Pass-through  (no gatekeeper — attack succeeds)":           run_passthrough,
    "🟢 Normal        (clean run, no injection)":                    None,
    "🔴 Easy          (radius=1, caught by immediate parent)":       run_easy,
    "🟠 Medium        (radius=2, caught by grandparent)":            run_medium,
    "🔥 Hard          (radius=4+, escalates to human flag)":         run_hard,
    "🔓 Resolve       (false positive — child justifies, granted)":  run_resolve,
    "🔍 Investigation (parent spawns investigator sub-agent)":       run_investigation,
    "⏱️  Timeout       (TTL expiry contains blast radius)":           run_timeout,
}

DESCRIPTIONS = {
    "⚡ Pass-through  (no gatekeeper — attack succeeds)":
        "No gatekeeper. Injection in calendar event causes agent to CC external address "
        "and pull financial data. Attack completes freely. Shows why identity-aware gating is needed.",
    "🟢 Normal        (clean run, no injection)":
        "Clean run — no injection. All credential requests are legitimate and approved. "
        "Shows the happy path: JIT credential issuance, TTL enforcement, attenuated scope.",
    "🔴 Easy          (radius=1, caught by immediate parent)":
        "Injection tells CalendarReader to email an external address. "
        "CalendarReader scope = {calendar} only — email request denied instantly by parent. "
        "Blast radius = 1 agent.",
    "🟠 Medium        (radius=2, caught by grandparent)":
        "3-level tree. Injection asks CalendarReader to pull finance_reports. "
        "CalendarReader → VacationManager (escalates) → Orchestrator (denies). Blast radius = 2.",
    "🔥 Hard          (radius=4+, escalates to human flag)":
        "5-level chain. Injection at leaf requests auth_tokens. Escalates all the way up "
        "— no agent can grant it. Root flags for human review. Blast radius = 4.",
    "🔓 Resolve       (false positive — child justifies, granted)":
        "CalendarReader finds meeting agenda asking for project status in the apology. "
        "Parent uncertain → child quotes calendar text as evidence → parent approves. "
        "Shows the system handles legitimate edge cases.",
    "🔍 Investigation (parent spawns investigator sub-agent)":
        "EmailSender receives instruction via external email reply to verify attendee list. "
        "Requests email_archive/read. Parent spawns Investigator → injection detected → denied.",
    "⏱️  Timeout       (TTL expiry contains blast radius)":
        "TTL = 5 s. Agent sends batch 1, injection distracts it, credential expires. "
        "Batches 2-3 blocked. Blast radius = 1 of 3 batches.",
}

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🔐 Secure Delegate Demo")
    st.caption("Attenuated delegation · JIT credentials · Prompt injection detection")
    st.divider()

    run_btn = st.button("▶  Run Scenario", type="primary", use_container_width=True)
    st.divider()

    scenario_name = st.selectbox("Scenario", list(SCENARIOS.keys()))
    st.info(DESCRIPTIONS[scenario_name])
    st.divider()

    use_real = st.toggle("Real Google Calendar + 1Password", value=False)
    if use_real:
        os.environ["USE_REAL_APIS"] = "true"
        st.success("Real APIs active")
    else:
        os.environ.pop("USE_REAL_APIS", None)

    speed = st.slider("Animation speed (s / step)", 0.3, 2.0, 0.8, 0.1)
    show_plan = st.toggle("Show Planner-Verifier tab", value=True)

# ── Task line + tree — ABOVE THE FOLD ─────────────────────────────────────────

st.caption(f"**Task:** {TASK}")
st.caption(
    "🔴 injected  ·  🟠 escalated (exposed)  ·  🔵 blocked  ·  "
    "← dashed = escalation path"
)

tree_box = st.empty()   # tree renders here, full width

# ── Everything else in tabs BELOW ─────────────────────────────────────────────

tab_labels = ["📊 Event Log", "🔑 Credentials", "🔎 Result"]
if show_plan:
    tab_labels.insert(0, "📋 Planner-Verifier")

tabs = st.tabs(tab_labels)

if show_plan:
    plan_tab, log_tab, cred_tab, result_tab = tabs
else:
    log_tab, cred_tab, result_tab = tabs
    plan_tab = None

# Persistent empty containers inside each tab
with log_tab:
    log_box = st.empty()
with cred_tab:
    cred_box = st.empty()
with result_tab:
    result_box = st.empty()
if plan_tab is not None:
    with plan_tab:
        st.markdown(
            "The **Planner** generates the expected tool sequence *before* the agent runs.  "
            "The **Verifier** checks each actual call against this plan at runtime — "
            "any step triggered by data the agent *read* (calendar, email) is flagged."
        )
        plan_col, verify_col = st.columns(2)
        with plan_col:
            st.subheader("Expected plan")
            plan_box = st.empty()
        with verify_col:
            st.subheader("Verifier log")
            verify_box = st.empty()
else:
    plan_box = None
    verify_box = None

# ── Render function ────────────────────────────────────────────────────────────

def render(forest: AgentForest, plan: list[dict], final: bool = False):
    # Tree — always first, full width
    tree_box.graphviz_chart(forest.to_graphviz(), use_container_width=True)

    # Event log tab
    rows = forest.events_as_rows()
    if rows:
        log_box.dataframe(
            pd.DataFrame(rows), use_container_width=True, hide_index=True, height=320
        )
    else:
        log_box.caption("No events yet...")

    # Credentials tab
    cred_rows = forest.credentials_as_rows()
    if cred_rows:
        cred_box.dataframe(
            pd.DataFrame(cred_rows), use_container_width=True, hide_index=True
        )
    else:
        cred_box.caption("No credentials issued yet.")

    # Planner-Verifier tab
    if plan_box is not None and plan:
        plan_box.json(plan)
        if rows:
            plan_tools = {s.get("tool", "") for s in plan}
            devs = [
                r["detail"][:60]
                for r in rows
                if "req_cred" in r["type"]
                and not any(p in r["detail"] for p in plan_tools)
            ]
            if devs and verify_box is not None:
                verify_box.warning("⚠️ Deviations:\n" + "\n".join(f"- {d}" for d in devs))
            elif verify_box is not None:
                verify_box.success("✅ All requests match the plan.")

    # Result tab (only meaningful at end)
    if final:
        inj_id, esc_ids, catch_id, _ = forest._escalation_chain()
        blast_r            = forest.blast_radius
        has_investigation  = any(e.event_type == "investigate" for e in forest.events)
        has_deny           = any(e.approved is False for e in forest.events)

        def _role(nid: str) -> str:
            return forest.nodes[nid].role if nid in forest.nodes else nid

        with result_box.container():
            if inj_id and not catch_id:
                st.error(
                    "💥 **NO GATEKEEPER — attack succeeded.**  "
                    "Blast radius: **unlimited.**  "
                    "This is what happens without identity-aware access control."
                )
                for line in forest.injection_trace():
                    st.code(line, language=None)

            elif inj_id and catch_id:
                esc_roles  = [_role(i) for i in esc_ids]
                catch_role = _role(catch_id)
                inj_role   = _role(inj_id)

                c1, c2, c3 = st.columns(3)
                c1.metric("Blast Radius", f"{blast_r} agent{'s' if blast_r != 1 else ''}")
                c2.metric("Injected at",  inj_role)
                c3.metric("Blocked by",   catch_role)

                if esc_roles:
                    path = " ← ".join([catch_role] + list(reversed(esc_roles)) + [inj_role])
                    st.warning(f"**Escalation path:** {path}  *(← dashed arrows in tree above)*")
                else:
                    st.success(
                        f"🛡️ Caught immediately by **{catch_role}** — "
                        "no escalation. Blast radius = 1."
                    )
                with st.expander("Full injection trace"):
                    for line in forest.injection_trace():
                        st.code(line, language=None)

            elif has_investigation and has_deny:
                inv_node = next(
                    (n for n in forest.nodes.values() if n.role == "Investigator"), None
                )
                deny_ev  = next(
                    (e for e in forest.events if e.event_type == "deny" and e.approved is False),
                    None,
                )
                st.warning(
                    "🔍 **Investigator pattern triggered.**  "
                    "Parent was uncertain about a credential request — spawned a dedicated "
                    f"Investigator ({inv_node.id if inv_node else '?'}).  "
                    "Investigator detected prompt injection. Request denied."
                )
                if deny_ev:
                    st.code(f"[{deny_ev.agent_role}] {deny_ev.detail}", language=None)

            elif has_deny:
                st.warning("🛡️  Some requests were blocked — see Event Log tab.")
            else:
                st.success("✅  Run completed cleanly — no suspicious activity detected.")


# ── Run ───────────────────────────────────────────────────────────────────────

if run_btn:
    forest            = AgentForest()
    forest.demo_delay = speed
    done_flag         = {"v": False}
    plan: list[dict]  = []

    if show_plan and plan_box is not None:
        with st.spinner("Generating plan..."):
            plan = generate_plan(TASK, ["read_calendar", "send_email", "read_email_archive"])

    scenario_fn = SCENARIOS[scenario_name]

    if scenario_fn is None:
        def scenario_fn(f: AgentForest):   # type: ignore[misc]
            orch = f.spawn_root("Orchestrator", TASK, {"calendar", "email"}, ttl_seconds=120)
            cal  = orch.spawn_child("CalendarReader", "Read calendar events", {"calendar"}, ttl_seconds=60)
            cred = cal.request_credential("calendar", "read", "Identify meetings to cancel")
            if cred and cal.use_credential(cred, "Read 3 events — bob@, alice@, charlie@, client@"):
                cal.status = "done"
            sndr = orch.spawn_child("EmailSender", "Send cancellation emails", {"email"}, ttl_seconds=60)
            cred = sndr.request_credential("email", "send", "Sending apologies to meeting attendees")
            if cred and sndr.use_credential(cred, "Sent apologies to all 4 attendees"):
                sndr.status = "done"
            orch.status = "done"

    def _run():
        scenario_fn(forest)
        done_flag["v"] = True

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    while not done_flag["v"]:
        render(forest, plan, final=False)
        time.sleep(0.35)

    thread.join()
    render(forest, plan, final=True)
