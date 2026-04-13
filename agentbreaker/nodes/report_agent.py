import json
import os
from datetime import datetime

import structlog
from openai import OpenAI

from agentbreaker.observability import get_langfuse
from agentbreaker.run_context import get_run_context
from agentbreaker.state import AgentState

log = structlog.get_logger()

SYSTEM_PROMPT = """You are a security report writer. Write a clear, professional security audit report in Markdown.

The report must include:
1. Executive Summary (2-3 sentences)
2. Findings table (attack name, class, severity, verdict)
3. Detailed findings — for each successful/partial attack:
   - Description
   - Reproduction steps
   - Evidence
   - Recommended fix
4. Statistics (attacks run, success rate by class)
5. Methodology note

Write in English. Be specific. Reference actual tool names and agent behavior from the evidence."""

SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _severity_sort_key(j: dict) -> int:
    if j.get("verdict") not in ("success", "partial"):
        return 0
    return SEVERITY_SCORE.get(j.get("severity", "low"), 0)


def report_agent_node(state: AgentState) -> dict:
    log.info("report_agent_started")

    config = state["config"]
    judgements = state.get("judgements", [])
    attack_plans = {a["id"]: a for a in state.get("attack_plans", [])}
    architecture_json = state.get("architecture_json", {})
    ctx = get_run_context()
    langfuse = get_langfuse()

    client = OpenAI(api_key=config["llm"]["api_key"], base_url=config["llm"]["base_url"])

    findings = [j for j in judgements if j.get("verdict") in ("success", "partial")]
    findings.sort(key=_severity_sort_key, reverse=True)

    stats = {"total": len(judgements), "success": 0, "failure": 0, "partial": 0, "inconclusive": 0}
    by_class: dict[str, dict] = {}
    for j in judgements:
        v = j.get("verdict", "inconclusive")
        stats[v] = stats.get(v, 0) + 1
        plan = attack_plans.get(j["attack_id"], {})
        cls = plan.get("class", "unknown")
        if cls not in by_class:
            by_class[cls] = {"total": 0, "success": 0}
        by_class[cls]["total"] += 1
        if v in ("success", "partial"):
            by_class[cls]["success"] += 1

    span = None
    if langfuse and ctx.langfuse_trace:
        span = ctx.langfuse_trace.span(name="report_agent", input={"findings_count": len(findings)})

    user_content = (
        f"Repository: {state.get('repo_url', 'unknown')}\n"
        f"Target endpoint: {state.get('target_endpoint', 'none')}\n"
        f"Agent architecture summary: {json.dumps(architecture_json, indent=2)[:1000]}\n\n"
        f"Attack statistics: {json.dumps(stats, indent=2)}\n"
        f"By class: {json.dumps(by_class, indent=2)}\n\n"
        f"Findings (successful/partial attacks):\n{json.dumps(findings, indent=2)}\n\n"
        f"All judgements:\n{json.dumps(judgements, indent=2)}"
    )

    response = client.chat.completions.create(
        model=config["llm"]["orchestrator_model"],
        temperature=0.3,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    )

    ctx.cost_tracker.record(
        "report_agent", config["llm"]["orchestrator_model"],
        response.usage.prompt_tokens, response.usage.completion_tokens,
    )

    report_md = response.choices[0].message.content.strip()

    repo_name = state.get("repo_url", "unknown").rstrip("/").split("/")[-1]
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/{repo_name}_{ts}.md"

    with open(report_path, "w") as f:
        f.write(report_md)

    log.info(
        "report_generated",
        report_path=report_path,
        findings_count=len(findings),
        total_cost_usd=ctx.cost_tracker.total_cost_usd,
    )

    if span:
        span.end(output={"report_path": report_path, "findings_count": len(findings)})

    return {
        "report_path": report_path,
        "current_step": "report_agent",
        "pipeline_status": "completed",
        "cost_tracker": ctx.cost_tracker.to_dict(),
    }
