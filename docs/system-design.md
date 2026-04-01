# System Design — AgentBreaker

## 1. Ключевые архитектурные решения

| # | Решение | Обоснование | Альтернатива и почему отклонена |
|---|---------|-------------|-------------------------------|
| AD-1 | **Двухмодельная privilege separation** — Analyzer LLM изолирован от Orchestrator LLM | Защита от indirect prompt injection через код анализируемого репо. Analyzer без tools, Orchestrator без доступа к сырому коду | Единая модель с тегами — не защищает от jailbreak через длинный контекст |
| AD-2 | **LangGraph как orchestration framework** | Типизированный state, встроенные checkpoints для resume, визуализация графа | LangChain agents — менее контролируемый flow; CrewAI — избыточная абстракция для одного агента |
| AD-3 | **BotHub OpenAI-совместимый proxy** для LLM-вызовов | Единый интерфейс, доступ к Claude Sonnet через OpenAI SDK, cost tracking на стороне proxy | Прямой Anthropic SDK — нет единого прокси для разных моделей |
| AD-4 | **ChromaDB локально** для OWASP RAG | Не требует внешних сервисов, встраиваемая, достаточна для PoC-масштаба (сотни документов) | Pinecone/Weaviate — overhead на деплой, не нужен для маленькой KB |
| AD-5 | **Persistent state через JSON-сериализацию** | Resume после сбоя staging endpoint; минимальная зависимость | SQLite — избыточно; Redis — внешний сервис |
| AD-6 | **Юзер сам поднимает staging endpoint** | Auto-deploy целевого агента — отдельный большой модуль (Docker, зависимости, env). Для PoC — overkill | Auto-deploy в Docker — отдельная работа на неделю+ |
| AD-7 | **Circuit breaker для LLM API** | Graceful degradation вместо бесконечных ретраев при недоступности BotHub | Простые retries — могут зациклиться, тратят бюджет |
| AD-8 | **LangFuse для LLM tracing + structlog + Grafana** | Полное покрытие обоих треков: агентские метрики (LangFuse) + инфраструктурные (Grafana) | Только логи — нет визуализации; только LangSmith — vendor lock-in |
| AD-9 | **typer + rich CLI** вместо Web UI / полноценного TUI | Минимальное время на UI, красивый вывод, достаточно для PoC-демо | Textual TUI — неделя работы на UI; Web UI — ещё больше |
| AD-10 | **YAML-конфиг** для параметров запуска | Читаемый, поддерживает вложенность, стандарт для ML-проектов | ENV vars — плоские; TOML — менее привычен |

## 2. Модули и их роли

### 2.1 Обзор модулей

```
┌──────────────────────────────────────────────────────────────┐
│                     CLI (typer + rich)                        │
│            input: GitHub repo URL + target endpoint           │
└─────────────────────────┬────────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────────┐
│                  Orchestrator (LangGraph)                     │
│         управляет pipeline, state, checkpoints               │
└──┬──────────┬───────────┬───────────┬──────────┬─────────────┘
   │          │           │           │          │
┌──▼───┐  ┌──▼────┐  ┌───▼────┐  ┌──▼─────┐ ┌──▼──────┐
│Repo  │  │Analyz.│  │Threat  │  │Attack  │ │Sandbox  │
│Cloner│  │LLM    │  │Planner │  │Generat.│ │Runner   │
│      │  │(изол.)│  │+ RAG   │  │        │ │         │
└──┬───┘  └──┬────┘  └───┬────┘  └──┬─────┘ └──┬──────┘
   │         │           │          │           │
   └─────────▼───────────▼──────────▼───────────▼──────────┐
             │            AgentState                        │
             │  (persistent, JSON checkpoints)              │
             └──────────────┬──────────────────────────────┘
                            │
             ┌──────────────▼──────────────────────────────┐
             │           Judge / Evaluator                  │
             └──────────────┬──────────────────────────────┘
                            │
             ┌──────────────▼──────────────────────────────┐
             │           Report Agent                       │
             │     markdown + GitHub Issues (HITL)          │
             └─────────────────────────────────────────────┘
```

| Модуль | Роль | Тип | Входы | Выходы |
|--------|------|-----|-------|--------|
| **CLI** | Точка входа, конфигурация, прогресс-бар | Детерминированный | repo URL, endpoint, YAML config | Запуск pipeline |
| **Repo Cloner** | Клонирование, фильтрация файлов, маскирование секретов | Детерминированный | repo URL | cloned_path, file_list |
| **Analyzer LLM** | Извлечение архитектуры агента из кода | LLM (изолированный) | Файлы репо в `<untrusted_repo_content>` | architecture JSON |
| **Threat Planner** | Построение модели угроз с OWASP RAG | LLM + RAG | architecture JSON | threat_model[] |
| **Attack Generator** | Генерация таргетированных атак 4 классов | LLM | architecture JSON + threat_model | attack_plans[] |
| **Sandbox Runner** | Исполнение атак по HTTP (single + multi-turn) | Детерминированный | attack_plans[], endpoint | attack_results[] |
| **Judge** | Независимая оценка результатов атак | LLM (дешёвая модель) | attack_results[] | judgements[] |
| **Report Agent** | Генерация отчёта + GitHub Issues | LLM + GitHub API | judgements[] | report.md, issues |
| **Observability** | Трейсинг, метрики, алерты | Инфраструктура | Все модули | LangFuse traces, Grafana dashboards |

### 2.2 Разделение LLM / детерминированного кода

| Задача | Исполнитель | Причина |
|--------|------------|---------|
| Клонирование репо, обход файлов, фильтрация | Детерминированный код | Надёжность, скорость |
| Поиск паттернов (`agent/`, `tools/`, `prompts/`) | Детерминированный код (regex + glob) | Точность |
| Маскирование секретов (`sk-*`, `ghp_*`, `password=`) | Детерминированный код (regex) | Безопасность |
| Интерпретация кода, извлечение архитектуры | **Analyzer LLM** | Требует понимания семантики |
| Построение модели угроз | **Orchestrator LLM** + OWASP RAG | Reasoning по контексту |
| Генерация атакующих payload-ов | **Orchestrator LLM** | Творческая задача |
| Исполнение HTTP-запросов (атаки) | Детерминированный код (httpx) | Воспроизводимость, контроль |
| Управление multi-turn сессиями | Детерминированный код + LLM для payload | Контроль над flow |
| Оценка результата атаки | **Judge LLM** | Независимая оценка |
| Порог severity / confidence | Детерминированный код (threshold) | Без галлюцинаций |
| Формулировка отчёта | **Orchestrator LLM** | Естественный язык |
| Создание GitHub Issues | Детерминированный код (GitHub API) | Контроль, HITL |

## 3. Основной Workflow

### 3.1 Happy Path

```
1. CLI: пользователь вводит repo URL + endpoint + config
2. Repo Cloner:
   a. git clone --depth=1
   b. фильтрация: glob по agent/, tools/, prompts/, *.py, *.ts (≤50 файлов)
   c. сканирование секретов → маскирование
   d. → cloned_path, file_list в state
3. Analyzer LLM (изолированный):
   a. получает файлы в <untrusted_repo_content>
   b. извлекает: tools[], system_prompt_fragments[], memory_type, call_chains[]
   c. возвращает JSON
   d. валидация JSON schema → retry если невалидный (до 2 раз)
   e. если retry не помог → переформулировка промпта (до 2 раз)
   f. → architecture_json в state
   ☑ CHECKPOINT: state сохраняется
4. Threat Planner:
   a. RAG-запрос к ChromaDB (OWASP LLM Top 10) по architecture_json
   b. LLM строит модель угроз: какие классы атак релевантны
   c. → threat_model[] в state
   ☑ CHECKPOINT
5. Attack Generator:
   a. LLM генерирует атаки 4 классов на основе architecture + threats
   b. дедупликация по хэшу payload
   c. → attack_plans[] в state
   ☑ CHECKPOINT
6. [Опционально] Если endpoint недоступен:
   → сохранить state, выдать partial report (план атак), EXIT
   → пользователь может resume когда endpoint поднимется
7. Sandbox Runner:
   a. health check endpoint
   b. single-turn атаки (prompt injection, tool abuse, data leakage)
   c. multi-turn сессии для memory poisoning (до 5 сессий, до 5 turns каждая)
   d. таймаут 30с на запрос, 2 мин на multi-turn сессию
   e. → attack_results[] в state
   ☑ CHECKPOINT
8. Judge:
   a. каждый результат оценивается отдельным LLM-вызовом
   b. confidence score, severity, категория
   c. confidence < 0.7 → помечается "unconfirmed"
   d. → judgements[] в state
   ☑ CHECKPOINT
9. Report Agent:
   a. LLM генерирует markdown-отчёт
   b. severity scoring (CVSS-подобное: impact × exploitability)
   c. → report.md в reports/
10. [HITL] GitHub Issues:
    a. показать превью Issues пользователю
    b. ждать подтверждения
    c. создать Issues (≤10 за сессию)
```

### 3.2 Failure Modes и Fallbacks

| Сбой | Детект | Реакция | Fallback |
|------|--------|---------|----------|
| Analyzer вернул невалидный JSON | JSON schema validation | 2 retry as-is → 2 retry с упрощённым промптом | Partial analysis с предупреждением |
| LLM API (BotHub) недоступен | Circuit breaker: 3 ошибки подряд | Graceful stop, сохранить checkpoint | Resume когда API восстановится |
| Staging endpoint недоступен | Health check перед атаками | Сгенерировать план атак без исполнения | Partial report + saved state для resume |
| Staging endpoint timeout (30с) | httpx timeout | Пометить атаку как `inconclusive` | Если >30% inconclusive → алерт |
| Judge даёт противоречивые оценки | consistency_score < 0.7 | Флаг `low_confidence` в отчёте | Рекомендация ручной проверки |
| Attack Generator генерирует дубли | Хэш-дедупликация payload | Автоматическое удаление дублей | Счётчик `duplicates_removed` |
| Репо без LLM-кода | Analyzer не нашёл паттерны | Ранний выход: "LLM agent not detected" | — |
| Репо > 50 релевантных файлов | Счётчик файлов после фильтрации | Обрезка по приоритету (agent/ > tools/ > остальное) | Предупреждение о неполном покрытии |
| Cost > $10 | Realtime token counting | Hard stop, partial report | Алерт на $8 (warning) |
| Монорепо / огромный репо | Размер после clone | Лимит 50 файлов + 10 мин timeout | Сообщение пользователю |

### 3.3 Circuit Breaker

```
States: CLOSED → OPEN → HALF_OPEN → CLOSED

CLOSED (нормальная работа):
  - каждый LLM-вызов проходит
  - считаем consecutive failures

  → 3 failures подряд → переход в OPEN

OPEN (API недоступен):
  - все LLM-вызовы блокируются
  - pipeline останавливается gracefully
  - state сохраняется в checkpoint
  - пользователю: "LLM API недоступен, state сохранён, 
    используйте --resume для продолжения"

  → через cooldown_period (60с) → переход в HALF_OPEN

HALF_OPEN (проверка):
  - один пробный вызов
  - если success → CLOSED, resume pipeline
  - если failure → обратно в OPEN
```

### 3.4 Retry Policy

```python
RETRY_CONFIG = {
    "max_retries_same_prompt": 2,      # retry с тем же промптом
    "max_retries_reformulated": 2,      # retry с упрощённым промптом
    "backoff_base_seconds": 2,          # exponential backoff: 2, 4 сек
    "circuit_breaker_threshold": 3,     # consecutive failures до OPEN
    "circuit_breaker_cooldown": 60,     # секунд до HALF_OPEN
}
```

## 4. State / Memory / Context Handling

### 4.1 AgentState (LangGraph)

```python
from typing import TypedDict, Optional

class AgentState(TypedDict):
    # Входные данные
    repo_url: str
    target_endpoint: str
    config: dict

    # Repo Cloner
    cloned_path: str
    file_list: list[str]

    # Analyzer
    architecture_json: Optional[dict]  # tools, memory_type, system_prompt_fragments, call_chains

    # Threat Planner
    threat_model: list[dict]           # [{class, description, severity, relevant_tools}]

    # Attack Generator
    attack_plans: list[dict]           # [{id, class, payload, target_tool, turns, expected_behavior}]

    # Sandbox Runner
    attack_results: list[dict]         # [{attack_id, response, status_code, latency_ms, turns_log}]

    # Judge
    judgements: list[dict]             # [{attack_id, verdict, confidence, severity, explanation}]

    # Report
    report_path: Optional[str]
    issues_created: list[str]          # GitHub issue URLs

    # Meta
    errors: list[dict]                 # [{step, error, timestamp}]
    retry_counts: dict[str, int]       # {step_name: count}
    cost_tracker: dict                 # {total_tokens, total_cost_usd, by_step}
    current_step: str
    pipeline_status: str               # running | paused | completed | failed
```

### 4.2 Persistent State (Resume)

State сериализуется в JSON после каждого checkpoint:

```
checkpoints/
  {repo_name}_{timestamp}/
    state.json          # полный AgentState
    metadata.json       # {created_at, last_step, status, cost}
```

**Resume flow:**
```
agentbreaker --resume checkpoints/my-agent_20260401/
→ загрузить state.json
→ определить current_step
→ продолжить pipeline с этого шага
```

### 4.3 Context Budget

| Вызов LLM | Estimated tokens | Модель |
|-----------|-----------------|--------|
| Analyzer (до 50 файлов) | ~30 000–80 000 input + ~2 000 output | Claude Sonnet |
| Threat Planner | ~5 000 input + ~2 000 output | Claude Sonnet |
| Attack Generator | ~8 000 input + ~5 000 output | Claude Sonnet |
| Judge (per attack, ~20 атак) | ~1 500 input + ~500 output × 20 | Claude Haiku |
| Report | ~10 000 input + ~3 000 output | Claude Sonnet |
| **Total estimate** | **~120 000–180 000 tokens** | **~$1–3 per audit** |

## 5. Retrieval-контур (OWASP RAG)

### 5.1 Архитектура

```
OWASP LLM Top 10 docs
        │
        ▼
  Chunking (по типам атак, ~500 tokens/chunk)
        │
        ▼
  Embedding (sentence-transformers, all-MiniLM-L6-v2)
        │
        ▼
  ChromaDB (локальная, persistent)
        │
        ▼
  Query: architecture_json → embedding → cosine similarity → top-k chunks
        │
        ▼
  Threat Planner LLM: architecture + relevant OWASP context → threat_model
```

### 5.2 Индексация

- **Источник:** OWASP Top 10 for LLM Applications (2025)
- **Структура индекса:** по типам атак (LLM01–LLM10)
- **Chunk size:** ~500 tokens с overlap 50
- **Metadata:** `{attack_type, severity, category, examples}`
- **Embedding model:** `all-MiniLM-L6-v2` (384 dims, CPU-friendly)
- **Поиск:** cosine similarity, top-5 chunks
- **Без reranking** — ресурсы ограничены, для PoC top-5 cosine достаточно
- **Предзаполнение:** скрипт `scripts/index_owasp.py` при первом запуске

## 6. Tool / API интеграции

### 6.1 Внешние сервисы

| Сервис | Назначение | Протокол | Auth |
|--------|-----------|----------|------|
| **BotHub Proxy** | LLM-вызовы (Claude Sonnet, Haiku) | OpenAI-совместимый REST API | API key в env |
| **GitHub API** | Клонирование репо, создание Issues | REST + git CLI | Personal access token в env |
| **Target Agent** | Staging endpoint тестируемого агента | OpenAI chat/completions совместимый | Опционально, из конфига |
| **ChromaDB** | OWASP knowledge base | Встроенная Python библиотека | Локально, без auth |
| **LangFuse** | LLM tracing и метрики | REST API | API key в env |

### 6.2 Sandbox Runner — HTTP-клиент

```python
# httpx async client с жёсткими ограничениями
SANDBOX_CONFIG = {
    "timeout_per_request": 30,          # секунд
    "timeout_per_session": 120,         # секунд (multi-turn)
    "max_attacks_per_session": 50,
    "max_multiturn_sessions": 5,
    "max_turns_per_session": 5,
    "allowed_endpoints": [
        "localhost:*",
        "127.0.0.1:*",
        # + домены из user config
    ],
    "http_client": "httpx.AsyncClient",
}
```

### 6.3 Контракты и ошибки

Подробные спецификации — в [docs/specs/tools-apis.md](specs/tools-apis.md).

## 7. Failure Modes, Guardrails и Security

### 7.1 Guardrails

| Guardrail | Что защищает | Реализация |
|-----------|-------------|------------|
| Privilege separation (AD-1) | От indirect injection через репо | Analyzer изолирован, Orchestrator не видит код |
| Endpoint whitelist | От атаки на production | Regex-проверка URL перед каждым запросом |
| HITL для Issues | От спама GitHub | Preview + confirmation, max 10/session |
| Cost tracking | От перерасхода бюджета | Realtime подсчёт, warning на $8, hard stop на $10 |
| Circuit breaker | От зацикливания при сбое API | 3 failures → OPEN → graceful stop |
| Secret masking | От утечки ключей в LLM-контекст | Regex-сканер перед Analyzer |
| Target response isolation | От memory poisoning AgentBreaker | `<target_agent_response>` теги, не сохраняются |
| Timeout enforcement | От зависания | 30с per request, 2мин per session, 10мин total |

### 7.2 Security Model

```
TRUST BOUNDARIES:
═══════════════════════════════════════════════════
  Untrusted:
    - Код анализируемого репозитория
    - Ответы тестируемого агента (staging endpoint)

  Semi-trusted:
    - JSON от Analyzer (может быть corrupted injection-ом)

  Trusted:
    - Orchestrator, Judge, Report Agent
    - OWASP knowledge base
    - Конфигурация пользователя
═══════════════════════════════════════════════════
```

### 7.3 Logging Policy

**Логируется:**
- Timestamps, repo URL (без credentials), step statuses, latencies
- Количество атак по классам, результаты (success/fail/inconclusive)
- Количество turns в memory poisoning, количество Issues
- Ошибки с traceback, cost per step

**НЕ логируется:**
- Системные промпты анализируемого агента
- Полные тексты атак (только хэш)
- Credentials (GitHub token, API keys)
- Ответы тестируемого агента в plaintext
- Содержимое tool call arguments

## 8. Технические и операционные ограничения

| Параметр | Ограничение | Обоснование |
|----------|-------------|-------------|
| p95 latency полного цикла | < 10 минут | UX, cost control |
| Размер репо (релевантных файлов) | ≤ 50 | Context window, latency |
| Max атак за сессию | 50 | Cost, time |
| Max multi-turn сессий | 5 | Cost (каждая = несколько LLM вызовов) |
| Max turns per session | 5 | Достаточно для memory poisoning PoC |
| Timeout per HTTP request | 30 секунд | Защита от зависания |
| Timeout per multi-turn session | 2 минуты | Защита от зависания |
| Cost per audit | < $10, warning на $8 | Бюджет |
| Max GitHub Issues per session | 10 | Anti-spam |
| LLM retry (same prompt) | 2 | Баланс надёжности и стоимости |
| LLM retry (reformulated) | 2 | Fallback стратегия |
| Circuit breaker threshold | 3 consecutive failures | Graceful degradation |
| Judge confidence threshold | ≥ 0.7 для confirmed | Снижение false positives |
| Checkpoint frequency | После каждого модуля | Resume capability |

## 9. Технологический стек

| Компонент | Технология | Версия |
|-----------|-----------|--------|
| Orchestration | LangGraph | latest |
| LLM Proxy | BotHub (OpenAI-compatible) | — |
| LLM (agent steps) | Claude Sonnet | via BotHub |
| LLM (Judge) | Claude Haiku | via BotHub |
| RAG vector store | ChromaDB | latest |
| Embeddings | sentence-transformers (all-MiniLM-L6-v2) | — |
| HTTP client | httpx (async) | latest |
| CLI framework | typer + rich | latest |
| Configuration | YAML (PyYAML / pydantic-settings) | — |
| LLM Tracing | LangFuse | latest |
| Logging | structlog → JSON | latest |
| Metrics visualization | Grafana (+ JSON log source) | latest |
| Language | Python 3.11+ | — |
| Package manager | uv / pip | — |

## 10. Ссылки на детальные спецификации

- [Retriever (OWASP RAG)](specs/retriever.md)
- [Tools / APIs](specs/tools-apis.md)
- [Memory / Context](specs/memory-context.md)
- [Orchestrator](specs/orchestrator.md)
- [Serving / Config](specs/serving-config.md)
- [Observability / Evals](specs/observability-evals.md)
- [Diagrams](diagrams/)
