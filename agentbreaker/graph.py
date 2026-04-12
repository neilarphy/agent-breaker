import os
import re
from datetime import datetime
from typing import Callable

import httpx
import yaml
from langgraph.graph import END, StateGraph

from agentbreaker.cost_tracker import CostLimitExceeded, CostTracker
from agentbreaker.nodes.analyzer import analyzer_node
from agentbreaker.nodes.attack_generator import attack_generator_node
from agentbreaker.nodes.judge import judge_node
from agentbreaker.nodes.repo_cloner import repo_cloner_node
from agentbreaker.nodes.report_agent import report_agent_node
from agentbreaker.nodes.sandbox_runner import sandbox_runner_node
from agentbreaker.nodes.threat_planner import threat_planner_node
from agentbreaker.observability import get_langfuse
from agentbreaker.state import AgentState


def _load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path) as f:
        raw = yaml.safe_load(f)

    def _expand(obj):
        if isinstance(obj, str):
            return re.sub(r"\$\{(\w+)\}", lambda m: os.getenv(m.group(1), m.group(0)), obj)
        if isinstance(obj, dict):
            return {k: _expand(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_expand(i) for i in obj]
        return obj

    return _expand(raw)


def _route_after_analyzer(state: AgentState) -> str:
    if state.get("architecture_json") is not None:
        not_agent = state["architecture_json"].get("not_an_llm_agent", False)
        if not_agent:
            return "not_agent"
        return "valid"
    if state.get("pipeline_status") == "failed":
        return "fail"
    retries = state.get("retry_counts", {}).get("analyzer", 0)
    if retries < 4:
        return "retry"
    return "fail"


def _route_sandbox_check(state: AgentState) -> str:
    endpoint = state.get("target_endpoint", "")
    if not endpoint:
        return "unavailable"
    try:
        r = httpx.get(f"{endpoint}/health", timeout=10)
        if r.status_code < 500:
            return "available"
    except Exception:
        pass
    return "unavailable"


def _wrap_with_cost_guard(node_fn: Callable) -> Callable:
    def wrapped(state: AgentState) -> dict:
        try:
            return node_fn(state)
        except CostLimitExceeded as e:
            from agentbreaker.observability import get_logger
            get_logger().error("cost_exceeded", error=str(e), cost=state["_cost_tracker"].total_cost_usd)
            return {
                "pipeline_status": "failed",
                "errors": state.get("errors", []) + [{
                    "step": state.get("current_step", "unknown"),
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }],
            }
    return wrapped


def build_graph(config_path: str = "config.yaml") -> StateGraph:
    config = _load_config(config_path)

    cost_tracker = CostTracker(
        pricing=config["llm"]["pricing"],
        warning_threshold=config["cost"]["warning_threshold_usd"],
        hard_limit=config["cost"]["hard_limit_usd"],
    )

    langfuse = get_langfuse()

    def init_node(state: AgentState) -> dict:
        trace = None
        if langfuse:
            trace = langfuse.trace(
                name="audit_session",
                metadata={
                    "repo_url": state.get("repo_url"),
                    "endpoint": state.get("target_endpoint"),
                },
            )
        return {
            "config": config,
            "_cost_tracker": cost_tracker,
            "_langfuse_trace": trace,
            "started_at": datetime.utcnow().isoformat(),
            "pipeline_status": "running",
            "errors": [],
            "retry_counts": {},
            "threat_model": [],
            "attack_plans": [],
            "attack_results": [],
            "judgements": [],
            "issues_created": [],
            "langfuse_trace_id": trace.id if trace else None,
        }

    graph = StateGraph(AgentState)

    graph.add_node("init", init_node)
    graph.add_node("repo_cloner", _wrap_with_cost_guard(repo_cloner_node))
    graph.add_node("analyzer", _wrap_with_cost_guard(analyzer_node))
    graph.add_node("threat_planner", _wrap_with_cost_guard(threat_planner_node))
    graph.add_node("attack_generator", _wrap_with_cost_guard(attack_generator_node))
    graph.add_node("sandbox_runner", sandbox_runner_node)
    graph.add_node("judge", _wrap_with_cost_guard(judge_node))
    graph.add_node("report_agent", _wrap_with_cost_guard(report_agent_node))

    graph.set_entry_point("init")
    graph.add_edge("init", "repo_cloner")
    graph.add_edge("repo_cloner", "analyzer")

    graph.add_conditional_edges("analyzer", _route_after_analyzer, {
        "valid": "threat_planner",
        "retry": "analyzer",
        "fail": "report_agent",
        "not_agent": END,
    })

    graph.add_edge("threat_planner", "attack_generator")

    graph.add_conditional_edges("attack_generator", _route_sandbox_check, {
        "available": "sandbox_runner",
        "unavailable": "report_agent",
    })

    graph.add_edge("sandbox_runner", "judge")
    graph.add_edge("judge", "report_agent")
    graph.add_edge("report_agent", END)

    return graph.compile()


def run_audit(repo_url: str, target_endpoint: str, config_path: str = "config.yaml") -> AgentState:
    app = build_graph(config_path)
    initial_state: AgentState = {
        "repo_url": repo_url,
        "target_endpoint": target_endpoint,
        "config": {},
        "cloned_path": "",
        "file_list": [],
        "architecture_json": None,
        "threat_model": [],
        "attack_plans": [],
        "attack_results": [],
        "judgements": [],
        "report_path": None,
        "issues_created": [],
        "errors": [],
        "retry_counts": {},
        "cost_tracker": {},
        "current_step": "init",
        "pipeline_status": "running",
        "started_at": "",
        "langfuse_trace_id": None,
    }
    final_state = app.invoke(initial_state)
    return final_state
