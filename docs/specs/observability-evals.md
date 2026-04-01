# Spec: Observability / Evals

## Обзор

Observability покрывает оба трека:
- **Агентский трек:** качество LLM, Judge consistency, attack specificity — через LangFuse
- **Инфраструктурный трек:** latency, availability, cost, errors — через structlog + Grafana

```
┌─────────────────────────────────────────────────────────┐
│                    AgentBreaker Pipeline                  │
│                                                          │
│  structlog ──→ logs/agentbreaker.jsonl ──→ Loki ──→ Grafana │
│  LangFuse SDK ──→ LangFuse Cloud/Self-hosted             │
│  Cost tracker ──→ AgentState + CLI output                 │
└─────────────────────────────────────────────────────────┘
```

## 1. Structured Logging (structlog)

### Формат

```json
{
  "timestamp": "2026-04-01T09:03:12.456Z",
  "level": "info",
  "event": "analyzer_completed",
  "step": "analyzer",
  "repo_url": "https://github.com/user/agent",
  "duration_ms": 12345,
  "tokens_used": 45000,
  "cost_usd": 0.45,
  "tools_found": 4,
  "memory_type": "chromadb",
  "retry_count": 0,
  "circuit_breaker_state": "CLOSED"
}
```

### События (events)

| Event | Level | Когда | Ключевые поля |
|-------|-------|-------|---------------|
| `pipeline_started` | info | Старт pipeline | repo_url, endpoint, config_hash |
| `repo_cloned` | info | После clone | files_count, clone_duration_ms |
| `secrets_masked` | warning | Найдены секреты | secrets_count, patterns_matched |
| `analyzer_started` | info | Начало анализа | files_count |
| `analyzer_completed` | info | JSON получен | tools_count, memory_type, duration_ms, tokens |
| `analyzer_retry` | warning | Retry | retry_count, reason (invalid_json / reformulated) |
| `analyzer_failed` | error | Все retry исчерпаны | retry_count, last_error |
| `rag_query` | debug | Запрос к ChromaDB | query_text_preview, results_count |
| `threat_model_built` | info | Модель угроз | threats_count, classes, duration_ms |
| `attacks_generated` | info | Атаки сгенерированы | total, by_class, duplicates_removed |
| `endpoint_health_check` | info | Health check | endpoint, status, latency_ms |
| `endpoint_unavailable` | warning | Endpoint down | endpoint, error |
| `attack_executed` | info | Одна атака | attack_id, class, status_code, latency_ms |
| `attack_timeout` | warning | Timeout атаки | attack_id, timeout_ms |
| `multiturn_session` | info | Multi-turn сессия | session_id, turns_count, duration_ms |
| `judge_result` | info | Оценка Judge | attack_id, verdict, confidence, severity |
| `judge_low_confidence` | warning | Confidence < 0.7 | attack_id, confidence |
| `report_generated` | info | Отчёт готов | report_path, findings_count |
| `issues_created` | info | GitHub Issues | issues_count, issue_urls |
| `cost_warning` | warning | Cost > $8 | current_cost, threshold |
| `cost_exceeded` | error | Cost > $10 | current_cost, hard_stop |
| `circuit_breaker_open` | error | CB → OPEN | failure_count, last_error |
| `circuit_breaker_half_open` | info | CB → HALF_OPEN | cooldown_elapsed |
| `circuit_breaker_closed` | info | CB → CLOSED | probe_success |
| `pipeline_completed` | info | Финиш | total_duration_ms, total_cost, findings_count |
| `pipeline_paused` | warning | Пауза | reason, checkpoint_path |
| `pipeline_resumed` | info | Resume | checkpoint_path, resume_step |

### Конфигурация structlog

```python
import structlog

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.WriteLoggerFactory(
        file=open("logs/agentbreaker.jsonl", "a")
    ),
)
```

## 2. LLM Tracing (LangFuse)

### Что трейсится

| Trace | Spans | Метрики |
|-------|-------|---------|
| `audit_session` (root) | Весь pipeline | total_duration, total_cost, total_tokens |
| → `analyzer` | LLM call(s) | prompt_tokens, completion_tokens, model, temperature |
| → `threat_planner` | RAG query + LLM call | rag_results_count, tokens |
| → `attack_generator` | LLM call | attacks_count, tokens |
| → `judge` (×N) | LLM call per attack | verdict, confidence, tokens |
| → `report` | LLM call | tokens |

### LangFuse Integration

```python
from langfuse import Langfuse
from langfuse.openai import openai  # patched client

langfuse = Langfuse(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_BASE_URL"),
)

# Каждый audit — отдельный trace
trace = langfuse.trace(
    name="audit_session",
    metadata={"repo_url": repo_url, "endpoint": endpoint},
)

# Каждый LLM call — span внутри trace
span = trace.span(
    name="analyzer",
    input={"files_count": len(files)},
)
# ... LLM call ...
span.end(
    output={"tools_found": 4, "memory_type": "chromadb"},
    metadata={"tokens": usage, "cost": cost},
)
```

### Метрики в LangFuse

| Метрика | Что показывает | Dashboard |
|---------|---------------|-----------|
| Latency per step | Время каждого LLM вызова | Timeline view |
| Tokens per step | Потребление токенов | Cost breakdown |
| Cost per audit | Общая стоимость | Trends |
| Model usage | Какая модель для какого шага | Model analytics |
| Error rate | % ошибок LLM вызовов | Reliability |
| Judge score distribution | Распределение confidence scores | Custom chart |

## 3. Grafana Dashboards

### Источник данных

```
structlog (JSON) → Loki → Grafana
```

### Dashboard: Pipeline Overview

| Panel | Query (LogQL) | Тип |
|-------|--------------|-----|
| Audits per day | `count_over_time({job="agentbreaker"} \|= "pipeline_completed")` | Bar chart |
| Avg pipeline duration | `avg(duration) by step` from pipeline_completed events | Time series |
| Success / Fail / Paused | Count by pipeline_status | Pie chart |
| Cost per audit | total_cost_usd from pipeline_completed | Stat + trend |

### Dashboard: LLM Health

| Panel | Описание | Тип |
|-------|---------|-----|
| LLM API latency (p50, p95) | Из structlog: duration_ms по LLM events | Time series |
| Error rate | Доля 4xx/5xx/timeout от всех LLM calls | Gauge |
| Circuit breaker state | Timeline CB states | State timeline |
| Token consumption | По шагам | Stacked bar |
| Cost burn rate | Cumulative cost over time | Time series |
| Retry rate | % вызовов с retry / total | Gauge |

### Dashboard: Attack Results

| Panel | Описание | Тип |
|-------|---------|-----|
| Findings by severity | High / Medium / Low / Unconfirmed | Pie chart |
| Findings by attack class | 4 classes breakdown | Bar chart |
| Inconclusive rate | % inconclusive attacks | Gauge |
| Judge confidence distribution | Histogram of confidence scores | Histogram |

### Alerts

| Alert | Условие | Severity | Channel |
|-------|---------|----------|---------|
| LLM API down | Circuit breaker OPEN | Critical | CLI + log |
| High cost | cost > $8 | Warning | CLI + log |
| Budget exceeded | cost > $10 | Critical | CLI + log + pipeline stop |
| High inconclusive rate | > 30% attacks inconclusive | Warning | Log |
| Judge inconsistency | consistency_score < 0.7 | Warning | Log |
| Pipeline failure | pipeline_status = "failed" | Error | Log |

## 4. Evals

### Агентские метрики (Agent Track)

| Метрика | Описание | Как измеряем | Цель PoC |
|---------|---------|-------------|----------|
| **Judge consistency** | Один результат — одна оценка при повторе | Двойной прогон Judge на тех же данных, сравнение | ≥ 90% |
| **Behavioral delta detection** | Judge детектирует разницу в поведении после memory poisoning | Paired sessions: clean vs poisoned, Judge оценивает | ≥ 80% |
| **Attack specificity** | Атаки ссылаются на конкретные элементы репо | Парсер: проверка наличия tool names / prompt fragments в payload | ≥ 60% |
| **Tool trace completeness** | Полный лог tool calls | Проверка наличия полного лога в attack_results | ≥ 95% |
| **Policy adherence** | Orchestrator не видит сырой код | Аудит логов: orchestrator никогда не вызывает read_file на репо | 100% |

### Инфраструктурные метрики (Infra Track)

| Метрика | Описание | Как измеряем | Цель PoC |
|---------|---------|-------------|----------|
| **p95 latency** | Время полного цикла | timestamp end - start | < 10 мин |
| **Successful repo parsing** | % репо успешно проанализированных | Analyzer success / total | ≥ 85% |
| **Cost per audit** | Стоимость одного аудита | Token counting × pricing | < $10 |
| **Resume success rate** | % успешных resume из checkpoint | resume success / attempts | ≥ 95% |
| **Circuit breaker recovery** | Время от OPEN до CLOSED | CB event timestamps | < 2 мин |
| **Uptime (LLM API)** | Доступность BotHub | Success calls / total calls | ≥ 99% |
| **Log completeness** | Все шаги залогированы | Check event types coverage | 100% |

### Eval Scripts

```bash
# Judge consistency eval
agentbreaker eval judge-consistency \
  --test-data data/eval/judge_pairs.json \
  --runs 2

# Attack specificity eval
agentbreaker eval attack-specificity \
  --report reports/my-agent_20260401.md \
  --architecture checkpoints/my-agent/state.json

# Full eval suite
agentbreaker eval all \
  --test-repo https://github.com/user/vulnerable-agent \
  --endpoint http://localhost:8000
```

### Eval Data

```
data/eval/
  judge_pairs.json          # Размеченные пары (attack_result, expected_verdict)
  memory_poisoning_pairs/   # Paired sessions для behavioral delta
  known_vulnerabilities.json # Ground truth для целевого тестового агента
```

## 5. Трейсинг через BotHub Proxy

### Что доступно через API proxy

BotHub как OpenAI-совместимый proxy возвращает `usage` в каждом ответе:

```json
{
  "usage": {
    "prompt_tokens": 1234,
    "completion_tokens": 567,
    "total_tokens": 1801
  }
}
```

Этого достаточно для:
- Token counting и cost tracking
- Latency (measure client-side)
- Error rates (HTTP status codes)

### Что НЕ доступно через proxy (и не нужно для PoC)

- GPU utilization, VRAM usage
- Model inference internals
- Queue depth на стороне провайдера

Для PoC proxy-level метрик достаточно. Разворачивать свою LLM для GPU-метрик — overkill.
