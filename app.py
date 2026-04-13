import os
import subprocess
import sys
import threading
import time

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(APP_DIR, "logs", "agentbreaker.jsonl")
os.makedirs(os.path.join(APP_DIR, "logs"), exist_ok=True)

st.set_page_config(
    page_title="AgentBreaker",
    page_icon="🔴",
    layout="wide",
)

st.title("🔴 AgentBreaker")
st.caption("Automated red-teaming for LLM agents")

STEP_ORDER = [
    ("repo_cloner", "Clone repository"),
    ("analyzer", "Analyze agent architecture"),
    ("threat_planner", "Build threat model"),
    ("attack_generator", "Generate attacks"),
    ("sandbox_runner", "Run attacks"),
    ("judge", "Evaluate results"),
    ("report_agent", "Generate report"),
]

SEVERITY_COLORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def _start_mock_agent():
    env = os.environ.copy()
    env["MOCK_AGENT_PORT"] = "8001"
    proc = subprocess.Popen(
        [sys.executable, "mock_agent/main.py"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    return proc


def _run_audit_thread(repo_url: str, endpoint: str, result_container: dict):
    try:
        from agentbreaker.graph import run_audit
        from agentbreaker.observability import setup_logging
        setup_logging()
        state = run_audit(repo_url, endpoint)
        result_container["state"] = state
        result_container["done"] = True
    except Exception as e:
        result_container["error"] = str(e)
        result_container["done"] = True


with st.sidebar:
    st.header("Configuration")

    gemini_key = st.text_input(
        "Gemini API Key",
        type="password",
        value=os.getenv("GEMINI_API_KEY", ""),
        help="Google AI Studio key — never shown in output",
    )
    if gemini_key:
        os.environ["GEMINI_API_KEY"] = gemini_key

    github_token = st.text_input(
        "GitHub Token (optional)",
        type="password",
        value=os.getenv("GITHUB_TOKEN", ""),
        help="Required only for creating GitHub Issues",
    )
    if github_token:
        os.environ["GITHUB_TOKEN"] = github_token

    st.divider()
    st.subheader("Mock Agent")
    if st.button("Start mock vulnerable agent"):
        if "mock_proc" not in st.session_state:
            st.session_state.mock_proc = _start_mock_agent()
            st.success("Mock agent started on :8001")
        else:
            st.info("Already running")

    if st.button("Index OWASP KB"):
        with st.spinner("Indexing..."):
            r = subprocess.run(
                [sys.executable, "scripts/index_owasp.py"],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                st.success(r.stdout.strip())
            else:
                st.error(r.stderr.strip())

col1, col2 = st.columns([3, 1])
with col1:
    repo_url = st.text_input(
        "GitHub Repository URL",
        placeholder="https://github.com/user/my-llm-agent",
    )
with col2:
    endpoint = st.text_input(
        "Target Endpoint",
        value=os.getenv("DEFAULT_ENDPOINT", "http://localhost:8001"),
    )

run_btn = st.button("🚀 Run Audit", type="primary", disabled=not repo_url)

if run_btn and repo_url:
    if not os.getenv("GEMINI_API_KEY"):
        st.error("Set your Gemini API Key in the sidebar first.")
        st.stop()

    st.divider()
    st.subheader("Pipeline Progress")

    step_cols = st.columns(len(STEP_ORDER))
    step_placeholders = {}
    for i, (step_id, label) in enumerate(STEP_ORDER):
        with step_cols[i]:
            step_placeholders[step_id] = st.empty()
            step_placeholders[step_id].markdown(f"⬜ {label}")

    log_area = st.empty()
    status_area = st.empty()

    result_container: dict = {"done": False, "state": None, "error": None}
    thread = threading.Thread(
        target=_run_audit_thread,
        args=(repo_url, endpoint, result_container),
        daemon=True,
    )
    thread.start()

    completed_steps = set()
    spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    frame_idx = 0

    while not result_container["done"]:
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-20:]

            for line in lines:
                import json as _json
                try:
                    entry = _json.loads(line)
                    step = entry.get("step") or entry.get("event", "").split("_")[0]
                    if step in step_placeholders and step not in completed_steps:
                        event = entry.get("event", "")
                        if "completed" in event or "generated" in event or "built" in event or "cloned" in event:
                            step_placeholders[step].markdown(f"✅ {dict(STEP_ORDER).get(step, step)}")
                            completed_steps.add(step)
                        elif "started" in event:
                            f_char = spinner_frames[frame_idx % len(spinner_frames)]
                            step_placeholders[step].markdown(f"{f_char} {dict(STEP_ORDER).get(step, step)}")
                except Exception:
                    pass

            frame_idx += 1
        except FileNotFoundError:
            pass

        time.sleep(0.3)

    for step_id, label in STEP_ORDER:
        if step_id not in completed_steps:
            step_placeholders[step_id].markdown(f"⬜ {label}")

    if result_container.get("error"):
        st.error(f"Pipeline error: {result_container['error']}")
        st.stop()

    final_state = result_container["state"]
    if not final_state:
        st.error("No result returned.")
        st.stop()

    st.divider()

    judgements = final_state.get("judgements", [])
    attack_plans = {a["id"]: a for a in final_state.get("attack_plans", [])}
    findings = [j for j in judgements if j.get("verdict") in ("success", "partial")]

    col_a, col_b, col_c, col_d = st.columns(4)
    col_a.metric("Total Attacks", len(judgements))
    col_b.metric("Successful", sum(1 for j in judgements if j.get("verdict") == "success"))
    col_c.metric("Partial", sum(1 for j in judgements if j.get("verdict") == "partial"))
    col_d.metric(
        "Cost",
        f"${final_state.get('cost_tracker', {}).get('total_cost_usd', 0):.4f}",
    )

    if findings:
        st.subheader("Findings")
        for j in sorted(findings, key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x.get("severity", "low"), 0), reverse=True):
            plan = attack_plans.get(j["attack_id"], {})
            sev = j.get("severity", "medium")
            icon = SEVERITY_COLORS.get(sev, "⚪")
            with st.expander(f"{icon} [{sev.upper()}] {plan.get('name', j['attack_id'])} — {j.get('verdict', '')}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Class:** {plan.get('class', '')}")
                    st.markdown(f"**Confidence:** {j.get('confidence', 0):.2f}")
                    st.markdown(f"**Explanation:** {j.get('explanation', '')}")
                with col2:
                    st.markdown(f"**Evidence:** {j.get('evidence', '')}")
                    st.markdown("**Payload:**")
                    st.code(plan.get("payload", ""), language="text")
    else:
        st.success("No successful attacks — agent appears resilient.")

    report_path = final_state.get("report_path")
    if report_path and os.path.exists(report_path):
        st.subheader("Report")
        with open(report_path) as f:
            report_md = f.read()
        st.markdown(report_md)
        st.download_button("Download Report", data=report_md, file_name=os.path.basename(report_path))

    eligible = [j for j in findings if j.get("confidence", 0) >= 0.7]
    if eligible and os.getenv("GITHUB_TOKEN"):
        st.divider()
        st.subheader("GitHub Issues")
        st.write(f"{len(eligible)} finding(s) ready to create as Issues.")
        if st.button("Create GitHub Issues"):
            from github import Github
            g = Github(os.getenv("GITHUB_TOKEN"))
            repo_name = "/".join(repo_url.rstrip("/").split("/")[-2:])
            try:
                gh_repo = g.get_repo(repo_name)
                for j in eligible[:10]:
                    plan = attack_plans.get(j["attack_id"], {})
                    title = f"[AgentBreaker] {plan.get('name', j['attack_id'])} — {j.get('severity', '').upper()}"
                    body = (
                        f"**Class:** {plan.get('class', '')}\n"
                        f"**Severity:** {j.get('severity', '')}\n"
                        f"**Confidence:** {j.get('confidence', 0):.2f}\n\n"
                        f"### Explanation\n{j.get('explanation', '')}\n\n"
                        f"### Evidence\n{j.get('evidence', '')}\n\n"
                        f"### Payload\n```\n{plan.get('payload', '')}\n```\n\n"
                        f"*Generated by AgentBreaker*"
                    )
                    issue = gh_repo.create_issue(title=title, body=body, labels=["security"])
                    st.success(f"Created: {issue.html_url}")
            except Exception as e:
                st.error(f"Failed: {e}")
