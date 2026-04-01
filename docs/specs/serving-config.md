# Spec: Serving / Config

## Запуск

### CLI Interface (typer + rich)

```bash
# Полный аудит
agentbreaker audit \
  --repo https://github.com/user/my-agent \
  --endpoint http://localhost:8000 \
  --config config.yaml

# Resume после сбоя
agentbreaker resume \
  --checkpoint checkpoints/my-agent_20260401_090000/

# Только статический анализ (без атак)
agentbreaker analyze \
  --repo https://github.com/user/my-agent

# Индексация OWASP KB
agentbreaker index-owasp \
  --source data/owasp_raw/

# Список сохранённых checkpoints
agentbreaker checkpoints list

# Просмотр стоимости последнего аудита
agentbreaker cost --last
```

### CLI Output (rich)

```
AgentBreaker v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Repo:     https://github.com/user/my-agent
Endpoint: http://localhost:8000
Config:   config.yaml

[1/7] Cloning repo...                    ✓ 23 files (0.8s)
[2/7] Analyzing architecture...           ✓ 4 tools, chromadb memory (12.3s)
[3/7] Building threat model...            ✓ 6 threats identified (3.1s)
[4/7] Generating attacks...               ✓ 18 attacks (4 classes) (5.2s)
[5/7] Running attacks...                  ✓ 15/18 completed, 3 inconclusive (45.0s)
[6/7] Judging results...                  ✓ 5 confirmed, 2 unconfirmed (8.4s)
[7/7] Generating report...                ✓ reports/my-agent_20260401.md

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Results: 5 vulnerabilities found (3 high, 2 medium)
Cost:    $1.87 (124,500 tokens)
Time:    1m 54s

Create GitHub Issues? [y/N]:
```

## Конфигурация

### config.yaml

```yaml
# AgentBreaker Configuration

# LLM Settings
llm:
  base_url: "${BOTHUB_BASE_URL}"          # env var reference
  api_key: "${BOTHUB_API_KEY}"            # env var reference
  agent_model: "claude-sonnet"            # Analyzer, Planner, Generator, Reporter
  judge_model: "claude-haiku"             # Judge (cheaper model)
  pricing:                                # per 1M tokens, USD
    claude-sonnet:
      input: 3.0
      output: 15.0
    claude-haiku:
      input: 0.25
      output: 1.25

# Target Agent
target:
  endpoint: "http://localhost:8000"
  api_key: "${TARGET_API_KEY}"            # optional
  model: "default"                        # model name for target
  allowed_endpoints:                      # whitelist
    - "localhost:*"
    - "127.0.0.1:*"
    # - "staging.mycompany.com:*"         # add custom domains

# GitHub
github:
  token: "${GITHUB_TOKEN}"
  max_issues_per_session: 10
  issue_labels: ["security", "agentbreaker"]

# Repo Analysis
analysis:
  max_files: 50
  file_patterns:
    - "agent/**"
    - "tools/**"
    - "prompts/**"
    - "**/*.py"
    - "**/*.ts"
    - "**/*.js"
  ignore_patterns:
    - "node_modules/**"
    - "venv/**"
    - "__pycache__/**"
    - "*.test.*"
    - "*.spec.*"

# Attack Settings
attacks:
  max_single_turn: 50
  max_multiturn_sessions: 5
  max_turns_per_session: 5
  timeout_per_request: 30                 # seconds
  timeout_per_session: 120                # seconds
  delay_between_attacks: 0.5              # seconds, avoid rate limiting
  classes:
    - prompt_injection
    - tool_abuse
    - data_leakage
    - memory_poisoning

# Cost Control
cost:
  warning_threshold: 8.0                  # USD
  hard_stop_threshold: 10.0              # USD
  max_llm_calls: 100

# Retry & Circuit Breaker
resilience:
  retry:
    max_same_prompt: 2
    max_reformulated: 2
    backoff_base_seconds: 2
    max_backoff_seconds: 16
  circuit_breaker:
    failure_threshold: 3
    cooldown_seconds: 60

# Judge
judge:
  confidence_threshold: 0.7              # minimum for "confirmed"
  consistency_check: true                # double-run for consistency eval

# Observability
observability:
  langfuse:
    enabled: true
    base_url: "${LANGFUSE_BASE_URL}"
    public_key: "${LANGFUSE_PUBLIC_KEY}"
    secret_key: "${LANGFUSE_SECRET_KEY}"
  logging:
    level: "INFO"                         # DEBUG | INFO | WARNING | ERROR
    format: "json"                        # json | console
    output: "logs/agentbreaker.jsonl"
    rotation_days: 7
  grafana:
    enabled: true
    loki_url: "${LOKI_URL}"               # optional

# Storage
storage:
  checkpoints_dir: "checkpoints/"
  reports_dir: "reports/"
  traces_dir: "traces/"
  chromadb_dir: "data/chromadb/"
  save_traces: false                      # full attack traces (--save-traces)

# Pipeline
pipeline:
  total_timeout: 600                      # 10 minutes, seconds
```

### Секреты

Все секреты — через environment variables (`.env` файл, не коммитится):

```bash
# .env
BOTHUB_BASE_URL=https://bothub.example.com
BOTHUB_API_KEY=sk-...
GITHUB_TOKEN=ghp_...
TARGET_API_KEY=...                        # optional
LANGFUSE_BASE_URL=https://langfuse.example.com
LANGFUSE_PUBLIC_KEY=pk-...
LANGFUSE_SECRET_KEY=sk-...
LOKI_URL=http://localhost:3100            # optional
```

### Валидация конфига

```python
from pydantic import BaseModel, validator

class LLMConfig(BaseModel):
    base_url: str
    api_key: str
    agent_model: str = "claude-sonnet"
    judge_model: str = "claude-haiku"

class TargetConfig(BaseModel):
    endpoint: str
    api_key: str | None = None
    allowed_endpoints: list[str] = ["localhost:*", "127.0.0.1:*"]

class Config(BaseModel):
    llm: LLMConfig
    target: TargetConfig | None = None
    # ... etc

    @validator("target")
    def validate_endpoint_in_whitelist(cls, v):
        if v and v.endpoint:
            # check against allowed_endpoints
            ...
```

### Версии моделей

| Компонент | Модель | Настраивается? |
|-----------|--------|---------------|
| Analyzer | config.llm.agent_model | Да |
| Threat Planner | config.llm.agent_model | Да |
| Attack Generator | config.llm.agent_model | Да |
| Judge | config.llm.judge_model | Да |
| Report Agent | config.llm.agent_model | Да |
| Embeddings | all-MiniLM-L6-v2 | Нет (hardcoded для PoC) |

### Приоритет конфигурации

```
CLI args > config.yaml > environment variables > defaults
```
