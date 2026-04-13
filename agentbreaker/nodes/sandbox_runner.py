import re
import time
from datetime import datetime

import httpx
import structlog

from agentbreaker.state import AgentState

log = structlog.get_logger()

ALLOWED_HOSTS = re.compile(r"^(localhost|127\.0\.0\.1|mock-agent)(:\d+)?$")


def _is_allowed_endpoint(endpoint: str) -> bool:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(endpoint)
        host = parsed.netloc or parsed.path
        return bool(ALLOWED_HOSTS.match(host))
    except Exception:
        return False


def _check_health(endpoint: str, timeout: int) -> bool:
    try:
        r = httpx.get(f"{endpoint}/health", timeout=timeout)
        return r.status_code < 500
    except Exception:
        return False


def _single_turn(client: httpx.Client, endpoint: str, payload: str, timeout: int) -> dict:
    start = time.time()
    try:
        resp = client.post(
            f"{endpoint}/v1/chat/completions",
            json={
                "model": "mock-agent-v1",
                "messages": [{"role": "user", "content": payload}],
            },
            timeout=timeout,
        )
        latency = int((time.time() - start) * 1000)
        body = resp.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {
            "status": "success",
            "status_code": resp.status_code,
            "response": content,
            "latency_ms": latency,
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "status_code": None, "response": "", "latency_ms": timeout * 1000}
    except Exception as e:
        return {"status": "error", "status_code": None, "response": str(e), "latency_ms": 0}


def _multi_turn(client: httpx.Client, endpoint: str, turn_sequence: list[str], config: dict) -> dict:
    session_id = f"poison_{int(time.time())}"
    timeout = config["sandbox"]["timeout_per_request"]
    turns_log = []

    for i, payload in enumerate(turn_sequence):
        start = time.time()
        try:
            resp = client.post(
                f"{endpoint}/v1/chat/completions",
                json={
                    "model": "mock-agent-v1",
                    "messages": [{"role": "user", "content": payload}],
                    "session_id": session_id,
                },
                timeout=timeout,
            )
            latency = int((time.time() - start) * 1000)
            body = resp.json()
            content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
            turns_log.append({
                "turn": i + 1,
                "payload": payload,
                "response": content,
                "status_code": resp.status_code,
                "latency_ms": latency,
            })
        except httpx.TimeoutException:
            turns_log.append({
                "turn": i + 1,
                "payload": payload,
                "response": "",
                "status_code": None,
                "latency_ms": timeout * 1000,
                "timed_out": True,
            })
            break

    try:
        client.delete(f"{endpoint}/sessions/{session_id}", timeout=5)
    except Exception:
        pass

    final_response = turns_log[-1]["response"] if turns_log else ""
    return {
        "status": "success",
        "session_id": session_id,
        "turns_log": turns_log,
        "response": final_response,
        "status_code": turns_log[-1].get("status_code") if turns_log else None,
        "latency_ms": sum(t["latency_ms"] for t in turns_log),
    }


def sandbox_runner_node(state: AgentState) -> dict:
    endpoint = state["target_endpoint"]
    config = state["config"]
    attack_plans = state["attack_plans"]

    sandbox_cfg = config["sandbox"]
    request_timeout = sandbox_cfg["timeout_per_request"]
    max_attacks = sandbox_cfg["max_attacks"]
    max_multiturn = sandbox_cfg["max_multiturn_sessions"]

    if not _is_allowed_endpoint(endpoint):
        log.warning("endpoint_not_whitelisted", endpoint=endpoint)
        return {
            "attack_results": [],
            "errors": state.get("errors", []) + [{
                "step": "sandbox_runner",
                "error": f"Endpoint not in whitelist: {endpoint}",
                "timestamp": datetime.utcnow().isoformat(),
            }],
            "current_step": "sandbox_runner",
        }

    log.info("endpoint_health_check", endpoint=endpoint)
    if not _check_health(endpoint, request_timeout):
        log.warning("endpoint_unavailable", endpoint=endpoint)
        return {
            "attack_results": [],
            "pipeline_status": "partial",
            "current_step": "sandbox_runner",
        }

    results = []
    multiturn_count = 0

    with httpx.Client() as client:
        for atk in attack_plans[:max_attacks]:
            atk_id = atk.get("id", "unknown")
            atk_class = atk.get("class", "")
            turns = atk.get("turns", 1)
            turn_sequence = atk.get("turn_sequence")

            if atk_class == "memory_poisoning" and turns > 1 and turn_sequence and multiturn_count < max_multiturn:
                log.info("multiturn_session", attack_id=atk_id, turns=turns)
                result = _multi_turn(client, endpoint, turn_sequence, config)
                result["attack_id"] = atk_id
                result["attack_class"] = atk_class
                result["is_multiturn"] = True
                multiturn_count += 1
            else:
                log.info("attack_executed", attack_id=atk_id, attack_class=atk_class)
                result = _single_turn(client, endpoint, atk.get("payload", ""), request_timeout)
                result["attack_id"] = atk_id
                result["attack_class"] = atk_class
                result["is_multiturn"] = False

                if result["status"] == "timeout":
                    log.warning("attack_timeout", attack_id=atk_id, timeout_ms=request_timeout * 1000)

            results.append(result)

    inconclusive = sum(1 for r in results if r["status"] in ("timeout", "error"))
    if results and inconclusive / len(results) > 0.3:
        log.warning("high_inconclusive_rate", rate=inconclusive / len(results))

    log.info("sandbox_runner_completed", total=len(results), multiturn=multiturn_count)

    return {
        "attack_results": results,
        "current_step": "sandbox_runner",
    }
