# Spec: Retriever (OWASP RAG)

## Назначение

Обеспечивает контекст из OWASP knowledge base для Threat Planner. Покрывает два стандарта:
- **OWASP Top 10 for LLM Applications** — уязвимости моделей
- **OWASP Top 10 for Agentic AI** — уязвимости агентных систем

Это критично для AgentBreaker, потому что мы аудитим именно **агентов**, а не просто LLM.

## Источники данных

| Источник | Покрытие | Объём |
|----------|---------|-------|
| OWASP Top 10 for LLM Applications (2025) | Уязвимости самих LLM | ~50 chunks |
| OWASP Top 10 for Agentic AI (2025) | Уязвимости агентных систем | ~50 chunks |

### OWASP Top 10 for LLM Applications

```
LLM01: Prompt Injection
LLM02: Insecure Output Handling
LLM03: Training Data Poisoning
LLM04: Model Denial of Service
LLM05: Supply Chain Vulnerabilities
LLM06: Sensitive Information Disclosure
LLM07: Insecure Plugin Design
LLM08: Excessive Agency
LLM09: Overreliance
LLM10: Model Theft
```

### OWASP Top 10 for Agentic AI

```
AGNT-01: Agentic Prompt Injection
AGNT-02: Agentic Tool Misuse
AGNT-03: Privilege Compromise
AGNT-04: Hallucinated Actions
AGNT-05: Identity Spoofing and Impersonation
AGNT-06: Uncontrolled Autonomy and Excessive Agency
AGNT-07: Repudiation and Lack of Accountability
AGNT-08: Vector and Embedding Weaknesses
AGNT-09: Improper Output Handling
AGNT-10: Misaligned Behaviors and Cascading Hallucinations
```

### Маппинг на классы атак AgentBreaker

| Класс атаки AgentBreaker | OWASP LLM | OWASP Agentic AI |
|---------------------------|-----------|-------------------|
| **Prompt Injection** | LLM01 | AGNT-01 |
| **Tool Abuse** | LLM07 | AGNT-02, AGNT-03, AGNT-06 |
| **Data Leakage** | LLM06 | AGNT-07, AGNT-09 |
| **Memory Poisoning** | LLM03 (аналог) | AGNT-04, AGNT-08, AGNT-10 |

## Индексация

### Структура хранения

```
data/chromadb/
  owasp_combined/          # единая ChromaDB collection
```

### Chunking Strategy

| Параметр | Значение | Обоснование |
|----------|---------|-------------|
| Chunk size | ~500 tokens | Баланс между контекстом и точностью |
| Overlap | 50 tokens | Сохранение контекста на границах |
| Splitting | По секциям (attack type / risk) | Семантическая целостность |
| Metadata per chunk | `{source, risk_id, risk_name, severity, category, is_agentic, has_examples}` | Фильтрация и ранжирование |

Ключевое: поле `is_agentic` позволяет фильтровать chunks по релевантности — если целевой агент использует tools, приоритет AGNT-02/AGNT-03/AGNT-06.

### Embedding Model

| Параметр | Значение |
|----------|---------|
| Model | `sentence-transformers/all-MiniLM-L6-v2` |
| Dimensions | 384 |
| Device | CPU |
| Обоснование | Лёгкая, CPU-friendly, достаточная для PoC (~100–150 chunks) |

## Поиск

### Query Pipeline

```
architecture_json
    │
    ▼
Query Builder:
    - tools[] → "Agent tools: {tool_names}, capabilities: {descriptions}"
    - memory_type → "Memory mechanism: {type}, persistence: {yes/no}"
    - call_chains → "Execution flow: {chains}"
    - framework → "Framework: {name}"
    │
    ▼
Embedding (same model)
    │
    ▼
ChromaDB cosine similarity search
    - filter: is_agentic=true (приоритет) + LLM fallback
    │
    ▼
Top-5 chunks (mixed: agentic + LLM)
    │
    ▼
Threat Planner LLM context
```

### Параметры поиска

| Параметр | Значение | Обоснование |
|----------|---------|-------------|
| Similarity metric | Cosine | Стандарт для sentence-transformers |
| Top-K | 5 | Достаточно контекста без перегрузки |
| Reranking | Нет | Ограничение по ресурсам (CPU only) |
| Filtering | Приоритет `is_agentic=true`, fallback на LLM risks | Агентные риски важнее для AgentBreaker |
| Adaptive query | Если архитектура имеет tools → вес AGNT-02; если memory → вес AGNT-08 | Контекстуальная релевантность |

### Стратегия поиска

```python
def search_owasp(architecture_json: dict, collection) -> list[dict]:
    query = build_query(architecture_json)

    # Сначала ищем по агентным рискам
    agentic_results = collection.query(
        query_texts=[query],
        n_results=3,
        where={"is_agentic": True},
    )

    # Дополняем LLM-рисками
    llm_results = collection.query(
        query_texts=[query],
        n_results=2,
        where={"is_agentic": False},
    )

    # Merge: 3 agentic + 2 LLM = 5 chunks
    return merge_results(agentic_results, llm_results)
```

## Предзаполнение

```bash
# Первый запуск — индексация обоих OWASP стандартов
python scripts/index_owasp.py \
  --source data/owasp_raw/ \
  --collection owasp_combined
```

Скрипт:
1. Читает OWASP LLM Top 10 + OWASP Agentic AI Top 10 из `data/owasp_raw/`
2. Чанкует по секциям + overlap
3. Добавляет metadata (source, risk_id, is_agentic)
4. Генерирует embeddings (all-MiniLM-L6-v2)
5. Сохраняет в ChromaDB persistent collection `owasp_combined`

### Структура raw данных

```
data/owasp_raw/
  llm/
    LLM01_prompt_injection.md
    LLM02_insecure_output.md
    ...
    LLM10_model_theft.md
  agentic/
    AGNT01_agentic_prompt_injection.md
    AGNT02_tool_misuse.md
    ...
    AGNT10_misaligned_behaviors.md
```

## Ограничения

| Ограничение | Значение |
|-------------|---------|
| Max chunks in context | 5 (3 agentic + 2 LLM) |
| Max tokens from RAG | ~2500 (5 × 500) |
| Collection size | ~100–150 chunks |
| Latency (query) | < 100ms (локально) |
| No reranking | Cosine similarity only |
| Manual update | При выходе новой версии OWASP |

## Failure Modes

| Сбой | Реакция |
|------|---------|
| ChromaDB collection не найдена | Ошибка при старте: "Run scripts/index_owasp.py first" |
| 0 результатов поиска | Threat Planner работает без RAG-контекста, warning в логах |
| Embedding model не скачана | Автоматическая загрузка при первом запуске (sentence-transformers) |
| Только LLM risks, нет agentic | Warning: "Agentic OWASP data not indexed, using LLM-only context" |
