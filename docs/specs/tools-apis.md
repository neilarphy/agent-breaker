# Spec: Tools / API Integrations

## Обзор внешних интеграций

| Сервис | Протокол | Auth | Критичность |
|--------|----------|------|------------|
| BotHub Proxy | OpenAI REST API | API key (env) | Критичный — без него pipeline не работает |
| GitHub API | REST + git CLI | PAT (env) | Для clone — критичный; для Issues — опциональный |
| Target Agent | OpenAI chat/completions compatible | Опционально (config) | Для атак — критичный; без него — partial report |
| ChromaDB | Python embedded | Нет (локально) | Для RAG — важный; без него — degraded threats |
| LangFuse | REST API | API key (env) | Опциональный — observability |

## BotHub Proxy (LLM API)

### Контракт

```
Endpoint: {BOTHUB_BASE_URL}/v1/chat/completions
Method: POST
Headers: Authorization: Bearer {BOTHUB_API_KEY}

Request body: OpenAI ChatCompletion format
  - model: "claude-sonnet" | "claude-haiku"
  - messages: [{role, content}]
  - temperature: 0.0–1.0
  - max_tokens: int
  - response_format: {"type": "json_object"}  # для Analyzer

Response: OpenAI ChatCompletion format
  - choices[0].message.content
  - usage: {prompt_tokens, completion_tokens, total_tokens}
```

### Модели и использование

| Модуль | Модель | Temperature | Max tokens | response_format |
|--------|--------|-------------|------------|-----------------|
| Analyzer LLM | claude-sonnet | 0.0 | 4096 | json_object |
| Threat Planner | claude-sonnet | 0.3 | 3000 | — |
| Attack Generator | claude-sonnet | 0.7 | 5000 | — |
| Judge | claude-haiku | 0.0 | 1000 | json_object |
| Report Agent | claude-sonnet | 0.3 | 5000 | — |

### Ошибки и обработка

| HTTP Status | Причина | Реакция |
|-------------|---------|---------|
| 200 | OK | Продолжить |
| 400 | Bad request | Log + fail step |
| 401 | Invalid API key | Fatal: остановить pipeline |
| 429 | Rate limit | Retry с exponential backoff (2, 4, 8 сек) |
| 500 | Server error | Retry (до 2 раз) → circuit breaker |
| 502/503 | Proxy/service down | Circuit breaker → OPEN |
| Timeout (30s) | Долгий ответ | Retry (до 2 раз) |

### Timeout

| Параметр | Значение |
|----------|---------|
| Connect timeout | 10 секунд |
| Read timeout | 60 секунд (LLM может думать долго) |
| Total timeout per call | 90 секунд |

## GitHub API

### Clone

```bash
git clone --depth=1 {repo_url} {tmp_dir}
```

| Параметр | Значение |
|----------|---------|
| Depth | 1 (только последний коммит) |
| Timeout | 60 секунд |
| Max repo size | Не проверяется до clone; фильтрация после |
| Auth | PAT в env (`GITHUB_TOKEN`) для rate limits |

### Issues

```
Endpoint: POST /repos/{owner}/{repo}/issues
Headers: Authorization: Bearer {GITHUB_TOKEN}

Request body:
  - title: str (vulnerability summary)
  - body: str (markdown: description, severity, reproduction steps)
  - labels: ["security", "agentbreaker"]

Ограничения:
  - Max 10 Issues за сессию
  - HITL: preview + confirmation перед созданием
  - Только после Judge с confidence ≥ 0.7
```

### Ошибки

| Ошибка | Реакция |
|--------|---------|
| 401 Unauthorized | Warning: Issues не будут созданы, report only |
| 403 Forbidden | Warning: нет прав на создание Issues |
| 404 Repo not found | Fatal при clone; warning при Issues |
| 422 Validation error | Log + skip this Issue |
| Rate limit (403) | Backoff, retry |

## Target Agent (Staging Endpoint)

### Контракт

Предполагается OpenAI chat/completions-совместимый endpoint:

```
Endpoint: {TARGET_ENDPOINT}/v1/chat/completions
Method: POST
Headers: Authorization: Bearer {TARGET_API_KEY}  # опционально

Request body:
  - model: str (из конфига или default)
  - messages: [{role: "user", content: attack_payload}]

Response:
  - choices[0].message.content  # ответ агента
```

### Multi-turn sessions

Для memory poisoning — несколько последовательных запросов с накоплением `messages[]`:

```python
# Сессия memory poisoning
messages = []
for turn in attack_plan.turns:
    messages.append({"role": "user", "content": turn.payload})
    response = await client.post(endpoint, json={"messages": messages})
    messages.append({"role": "assistant", "content": response.content})
    # → записать в turns_log
```

### Ограничения и защита

| Параметр | Значение |
|----------|---------|
| Timeout per request | 30 секунд |
| Timeout per session | 120 секунд |
| Max single-turn attacks | 50 |
| Max multi-turn sessions | 5 |
| Max turns per session | 5 |
| Whitelist | `localhost:*`, `127.0.0.1:*`, + конфиг |
| HITL | Confirmation перед атаками на внешний endpoint |

### Side Effects

| Side Effect | Описание | Митигация |
|-------------|---------|-----------|
| Memory poisoning | Атака изменяет long-term memory целевого агента | Предупреждение пользователю; только staging |
| State mutation | Multi-turn меняет session state | Каждая сессия — новый conversation_id |
| Rate limiting | Много запросов могут вызвать throttling | Пауза между атаками (configurable) |

### Ошибки

| Ошибка | Реакция |
|--------|---------|
| Connection refused | Endpoint недоступен → partial report |
| Timeout (30s) | Атака = `inconclusive` |
| 4xx | Log + mark attack `error` |
| 5xx | Retry 1 раз → mark `error` |
| >30% inconclusive | Alert: endpoint нестабилен |

## ChromaDB (Embedded)

### Контракт

```python
import chromadb

client = chromadb.PersistentClient(path="data/chromadb")
collection = client.get_collection("owasp_llm_top10")

results = collection.query(
    query_texts=["LLM agent with file_read tool and ChromaDB memory"],
    n_results=5,
)
# → results["documents"], results["metadatas"], results["distances"]
```

### Ошибки

| Ошибка | Реакция |
|--------|---------|
| Collection not found | Fatal: "Run scripts/index_owasp.py" |
| Empty results | Warning: Threat Planner без RAG-контекста |
| Corrupted DB | Recreate: re-run index_owasp.py |
