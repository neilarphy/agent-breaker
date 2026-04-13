from typing import TypedDict, Optional


class AgentState(TypedDict):
    repo_url: str
    target_endpoint: str
    config: dict

    cloned_path: str
    file_list: list[str]
    file_contents: dict[str, str]

    architecture_json: Optional[dict]

    threat_model: list[dict]

    attack_plans: list[dict]

    attack_results: list[dict]

    judgements: list[dict]

    report_path: Optional[str]
    issues_created: list[str]

    errors: list[dict]
    retry_counts: dict[str, int]
    cost_tracker: dict
    current_step: str
    pipeline_status: str
    started_at: str
    langfuse_trace_id: Optional[str]
