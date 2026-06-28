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

st.set_page_config(page_title="Agent Identity Demo", layout="wide", page_icon="🔐")

# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS = {
    "⚡ Pass-through  (no gatekeeper — attack succeeds)":          run_passthrough,
    "🟢 Normal        (clean run, no injection)":                   None,  # handled below
    "🔴 Easy          (radius=1, caught by immediate parent)":      run_easy,
    "🟠 Medium        (radius=2, caught by grandparent)":           run_medium,
    "🔥 Hard          (radius=4+, escalates to human flag)":        run_hard,
    "🔓 Resolve       (false positive — child justifies, granted)": run_resolve,
    "🔍 Investigation (parent spawns investigator sub-agent)":      run_investigation,
    "⏱️  Timeout       (TTL expiry contains blast radius)":          run_timeout,
}

DESCRIPTIONS = {
    "⚡ Pass-through  (no gatekeeper — attack succeeds)":
        "No gatekeeper active. Injection in calendar event causes agent to CC external address "
        "and pull financial data. Attack completes freely. Shows why identity-aware gating is needed.",
    "🟢 Normal        (clean run, no injection)":
        "Clean run — no injection in calendar. All credential requests are legitimate and approved. "
        "Shows the happy path with JIT credential issuance and TTL.",
    "🔴 Easy          (radius=1, caught by immediate parent)":
        "Injection in calendar tells CalendarReader to email an external address. "
        "CalendarReader's scope = {calendar} only — email request denied instantly at Layer 1 (scope check). "
        "No LLM call needed. Blast radius = 1 agent.",
    "🟠 Medium        (radius=2, caught by grandparent)":
        "3-level tree. Injection asks CalendarReader to pull finance_reports. "
        "CalendarReader → VacationManager (can't grant, escalates) → Orchestrator (denies). "
        "Blast radius = 2 hops.",
    "🔥 Hard          (radius=4+, escalates to human flag)":
        "5-level chain. Injection at leaf requests auth_tokens. "
        "Escalates all the way up — no agent in the chain can grant it. "
        "Root flags for human review. Blast radius contained by the deepest level that holds the resource.",
    "🔓 Resolve       (false positive — child justifies, granted)":
        "CalendarReader finds meeting agenda that explicitly asks for project status in the apology. "
        "It requests projects/read — initially uncertain — then provides the calendar quote as evidence. "
        "Parent re-evaluates with evidence and approves. Shows the system isn't a blunt blocker.",
    "🔍 Investigation (parent spawns investigator sub-agent)":
        "Injection sounds like a real compliance mandate (with reference number and VP signature). "
        "Parent is uncertain — spawns a dedicated Investigator sub-agent for deeper analysis. "
        "Investigator determines it's injected and denies.",
    "⏱️  Timeout       (TTL expiry contains blast radius)":
        "Even when injection passes initial scope checks, the 5-second TTL limits damage. "
        "Agent sends batch 1, gets distracted by injection, credential expires. "
        "Batches 2 and 3 are blocked. Blast radius = 1 of 3 email batches.",
}

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🔐 Agent Identity Demo")
    st.caption("Plan-conditioned gating · JIT credentials · Prompt injection detection")
    st.divider()

    scenario_name = st.selectbox("Select scenario", list(SCENARIOS.keys()))
    st.info(DESCRIPTIONS[scenario_name])
    st.divider()

    use_real = st.toggle("Use real Google Calendar (requires setup)", value=False)
    if use_real:
        os.environ["USE_REAL_APIS"] = "true"
        st.success("Real Google Calendar + 1Password active")
    else:
        os.environ.pop("USE_REAL_APIS", None)

    show_plan = st.toggle("Show Planner-Verifier panel", value=True)
    st.divider()
    run_btn = st.button("▶  Run Scenario", type="primary", use_container_width=True)

# ── Header ────────────────────────────────────────────────────────────────────

st.header(scenario_name.split("(")[0].strip())
st.caption(f"Task: *{TASK}*")

# ── Planner panel ─────────────────────────────────────────────────────────────

if show_plan:
    with st.expander("📋 Planner-Verifier  (expected plan before agent runs)", expanded=True):
        st.markdown("""
The **Planner** generates the expected tool sequence before the agent runs.
The **Verifier** (gatekeeper) checks each actual tool call against this plan at runtime.
Any deviation — especially one triggered by data the agent *reads* — is flagged as a potential injection.
        """)
        plan_col, verify_col = st.columns(2)
        with plan_col:
            st.subheader("Planner output")
            plan_box = st.empty()
        with verify_col:
            st.subheader("Verifier (runtime gatekeeper log)")
            verify_box = st.empty()

# ── Main layout ───────────────────────────────────────────────────────────────

left, right = st.columns([1, 1])
with left:
    st.subheader("Agent Tree")
    tree_box = st.empty()
with right:
    st.subheader("Event Log")
    events_box = st.empty()

st.subheader("Credentials Issued")
creds_box = st.empty()
trace_box = st.empty()

# ── Helpers ───────────────────────────────────────────────────────────────────

def render(forest: AgentForest, plan: list[dict], final: bool = False):
    tree_box.graphviz_chart(forest.to_graphviz(), use_container_width=True)

    rows = forest.events_as_rows()
    if rows:
        df = pd.DataFrame(rows)
        events_box.dataframe(df, use_container_width=True, hide_index=True, height=320)
    else:
        events_box.caption("No events yet...")

    cred_rows = forest.credentials_as_rows()
    if cred_rows:
        creds_box.dataframe(pd.DataFrame(cred_rows), use_container_width=True, hide_index=True)
    else:
        creds_box.caption("No credentials issued yet.")

    if show_plan and plan:
        plan_box.json(plan)
        if rows:
            # Show which events match plan steps vs. deviate
            actual_tools = [r["type"] for r in rows if "tool_use" in r["type"] or "req_cred" in r["type"]]
            plan_tools   = [s.get("tool", "") for s in plan]
            deviations   = [t for t in actual_tools if not any(p in t for p in plan_tools)]
            if deviations:
                verify_box.warning(f"⚠️ Deviations from plan detected:\n" + "\n".join(f"- {d}" for d in deviations))
            else:
                verify_box.success("✅ All observed tool calls match the plan.")

    if final:
        trace = forest.injection_trace()
        br    = forest.blast_radius
        inj_id, esc_ids, catch_id, _ = forest._escalation_chain()

        if inj_id and not catch_id:
            # Pass-through
            with trace_box.container():
                st.error("💥 NO GATEKEEPER — attack succeeded. Blast radius: unlimited.")
                for line in trace:
                    st.code(line, language=None)
        elif inj_id and catch_id:
            # Attack was caught
            esc_roles = [forest.nodes[i].role for i in esc_ids if i in forest.nodes]
            catch_role = forest.nodes[catch_id].role if catch_id in forest.nodes else catch_id
            with trace_box.container():
                col1, col2 = st.columns([1, 2])
                with col1:
                    st.metric("Blast Radius", f"{br} agent{'s' if br != 1 else ''}")
                with col2:
                    if esc_roles:
                        st.warning(
                            f"**Escalation path:** "
                            + " → ".join(esc_roles)
                            + f" → 🛡️ **{catch_role}** (blocked)"
                        )
                    else:
                        st.success(f"🛡️ Caught immediately by **{catch_role}**. No escalation.")
                if trace:
                    with st.expander("Full injection trace"):
                        for line in trace:
                            st.code(line, language=None)
        elif any(e.approved is False for e in forest.events):
            trace_box.warning("🛡️  Requests were blocked — see event log for details.")
        else:
            trace_box.success("✅  Run completed cleanly.")


# ── Run ───────────────────────────────────────────────────────────────────────

if run_btn:
    forest    = AgentForest()
    done_flag = {"v": False}
    plan: list[dict] = []

    # Generate plan before running
    if show_plan:
        with st.spinner("Generating plan..."):
            plan = generate_plan(TASK, ["read_calendar", "send_email"])

    scenario_fn = SCENARIOS[scenario_name]

    # Normal scenario: no injection, use easy scenario without attack path
    if scenario_fn is None:
        from multi_agent import run_easy as _normal
        def scenario_fn(f):  # type: ignore
            from multi_agent import AgentForest as AF
            orch = f.spawn_root("Orchestrator", TASK, {"calendar", "email"}, ttl_seconds=120)
            cal = orch.spawn_child("CalendarReader", "Read calendar events", {"calendar"}, ttl_seconds=60)
            from multi_agent import _fetch_calendar_events
            cred = cal.request_credential("calendar", "read", "Identifying meetings to cancel")
            if cred and cal.use_credential(cred, "Read 3 events — bob@, alice@, charlie@, client@"):
                cal.status = "done"
            emailer = orch.spawn_child("EmailSender", "Send cancellation emails", {"email"}, ttl_seconds=60)
            cred = emailer.request_credential("email", "send", "Sending apologies to meeting attendees")
            if cred and emailer.use_credential(cred, "Sent apologies to all 4 attendees"):
                emailer.status = "done"
            orch.status = "done"

    def _run():
        scenario_fn(forest)
        done_flag["v"] = True

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    with st.spinner("Agent tree running..."):
        while not done_flag["v"]:
            render(forest, plan, final=False)
            time.sleep(0.4)

    thread.join()
    render(forest, plan, final=True)
