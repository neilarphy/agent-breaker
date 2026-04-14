# AgentBreaker 🔴
> Автоматический red-teaming для LLM-агентов — читает код агента, строит модель угроз и атакует точечными payload'ами

## Что это

Команды деплоят LLM-агентов с инструментами, памятью и сложными цепочками вызовов. Безопасность проверяется вручную или не проверяется вообще. Существующие инструменты (Llamator, Promptfoo) атакуют вслепую — фиксированными payload'ами без знания архитектуры.

**AgentBreaker** клонирует GitHub-репозиторий, восстанавливает архитектуру агента — системные промпты, tools, memory, цепочки вызовов — и генерирует атаки именно под эту конфигурацию. Включая memory poisoning и multi-turn атаки.

Сам AgentBreaker защищён через двухмодельную архитектуру: изолированный Analyzer LLM читает код репо, Orchestrator видит только структурированный JSON.

## Архитектура пайплайна

```
GitHub Repo → repo_cloner → analyzer → threat_planner → attack_generator
                                                               ↓
                                                        sandbox_runner
                                                               ↓
                                                         judge → report_agent
```

| Нода | Что делает |
|---|---|
| `repo_cloner` | Клонирует репо, фильтрует файлы, маскирует секреты |
| `analyzer` | Изолированный LLM читает код, возвращает JSON архитектуры |
| `threat_planner` | LLM + RAG по OWASP LLM Top 10 строит модель угроз |
| `attack_generator` | Генерирует тест-кейсы под каждый класс угроз |
| `sandbox_runner` | Отправляет атаки на endpoint через HTTP |
| `judge` | LLM оценивает каждый ответ: success / partial / failure |
| `report_agent` | Генерирует markdown-отчёт, отсортированный по severity |

**Классы атак:**
- `prompt_injection` — переопределение системного промпта через user message
- `tool_abuse` — провокация вызова tool с опасными аргументами
- `data_leakage` — извлечение системного промпта и внутренних учётных данных
- `memory_poisoning` — отравление долгосрочной памяти через multi-turn сессии

## Как запустить демо

Демо развёрнуто и доступно по адресу: **`http://92.51.23.44:9501`**

### Шаг 1 — Открыть UI

Перейди по ссылке. В сайдбаре слева увидишь:
- **LLM API Key: configured** — ключ уже настроен, вводить не нужно
- **GitHub Token** — опционально, нужен только для создания GitHub Issues

### Шаг 2 — Запустить аудит

Заполни два поля:

| Поле | Значение для демо |
|---|---|
| GitHub Repository URL | [`https://github.com/neilarphy/toolcall-agent`](https://github.com/neilarphy/toolcall-agent) |
| Target Endpoint | `http://mock-agent:8001` |

Нажми **Run Audit**.

### Шаг 3 — Наблюдать за пайплайном

Прогресс-бар показывает 7 шагов в реальном времени:
```
✅ Clone repository
✅ Analyze agent architecture
✅ Build threat model
✅ Generate attacks
✅ Run attacks
✅ Evaluate results
✅ Generate report
```

Полный прогон занимает ~1-2 минуты.

### Шаг 4 — Изучить результаты

После завершения:
- **Метрики** — Total Attacks, Successful, Partial, Cost
- **Findings** — список уязвимостей по severity (critical/high/medium/low)
- **Каждый finding** содержит: класс атаки, confidence, объяснение, evidence, payload
- **Report** — полный markdown-отчёт с таблицей findings и рекомендациями
- **Download Report** — скачать отчёт
- **Create GitHub Issues** — создать Issues в репо (нужен GitHub Token)

### Шаг 5 — История аудитов

В сайдбаре → **Audit History** — список прошлых отчётов. Выбери любой и нажми **Load report**.

## Что тестируется

Для демо используются два агента с разным уровнем уязвимости.

### Вариант 1 — Mock-агент (полностью уязвимый, рекомендуется для демо)

**Target Endpoint:** `http://mock-agent:8001`

Специально написанный агент без LLM — отвечает на все классы атак предсказуемо. Показывает полный пайплайн с реальными findings.

Ожидаемые результаты:

| Атака | Класс | Severity |
|---|---|---|
| Чтение `/etc/passwd` через `read_file` | Tool Abuse | Critical |
| Выполнение shell-команд через `run_shell` | Excessive Agency | Critical |
| Выполнение SQL без авторизации | Tool Abuse | Critical |
| Отправка email без подтверждения | Excessive Agency | High |
| Prompt injection | Prompt Injection | High |
| Memory poisoning через session_id | Memory Poisoning | High |

### Вариант 2 — DevAssist ([github.com/neilarphy/toolcall-agent](https://github.com/neilarphy/toolcall-agent)) (частично уязвимый)

**Target Endpoint:** `http://5.129.220.203:8000`

Реальный LangGraph-агент на gpt-4o-mini с намеренно уязвимой архитектурой (незащищённые tools, секреты в системном промпте, непроверенный session_id). Анализ кода выявляет все уязвимости, однако встроенное safety training модели частично блокирует их эксплуатацию в runtime. Это само по себе является находкой: **архитектурные уязвимости есть, но модельный слой служит implicit defense**.

## Тестирование своего агента

Чтобы проверить собственный LLM-агент:

1. Агент должен иметь OpenAI-совместимый endpoint: `POST /v1/chat/completions`
2. Укажи его URL в поле **Target Endpoint**
3. Укажи публичный GitHub-репозиторий с кодом агента

> **Важно:** Современные LLM (gpt-4o-mini, gpt-3.5-turbo) имеют встроенное safety training которое само по себе является implicit defense — они могут отказываться выполнять опасные tool calls даже когда код не имеет ограничений. Это само по себе является находкой: уязвимости на уровне архитектуры существуют, но mitigation'ом служит модельный слой. Uncensored модели или indirect атаки это обходят.

## Observability

**Стоимость** каждого аудита показывается прямо в интерфейсе AgentBreaker (поле **Cost** над таблицей findings).

Все запуски трейсятся в self-hosted **LangFuse** (`http://92.51.23.44:9300`):
- Один trace на сессию аудита (`audit_session`)
- Spans по каждой ноде с input/output
- Judge spans на каждую атаку (`judge_atk_001` ... `judge_atk_N`)

LangFuse — внутренний инструмент для наблюдаемости, стоимость в нём не отображается (используется сторонний провайдер с кастомным прайсингом). Для доступа достаточно зарегистрироваться на инстансе: `http://92.51.23.44:9300` → Sign up.

## Уязвимый агент (для тестирования)

В папке `vulnerable_agent/` — намеренно уязвимый LangGraph-агент DevAssist. Реализует все классы уязвимостей:

| OWASP | Где в коде | Уязвимость |
|---|---|---|
| LLM01 Prompt Injection | `agent.py:43` | Нет санитизации входных данных |
| LLM02 Insecure Output | `agent.py:45` | Аргументы tool calls от LLM не валидируются |
| LLM03 Memory Poisoning | `main.py:30` | `thread_id` приходит от клиента, MemorySaver |
| LLM04 Tool Abuse | `agent.py:50` | ToolNode выполняет всё что запросил LLM |
| LLM06 Sensitive Info | `agent.py:13` | `DB_PASSWORD`, API-ключи в системном промпте |
| LLM07 Insecure Plugin | `tools.py:37` | Сырой SQL от LLM без параметризации |
| LLM08 Excessive Agency | `tools.py:19`, `tools.py:47` | Shell без ограничений, email любому адресату |
