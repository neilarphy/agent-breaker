# Deploy on VPS

```bash
git clone <your-repo> agentbreaker && cd agentbreaker

cp .env.example .env
# Edit .env — add GEMINI_API_KEY, LANGFUSE keys, optionally GITHUB_TOKEN

# First run: index OWASP knowledge base
docker compose run --rm agentbreaker python scripts/index_owasp.py

# Start all services
docker compose up -d

# LangFuse UI → http://<vps-ip>:3000  (create account on first visit)
# AgentBreaker UI → http://<vps-ip>:8501
# Mock agent → http://<vps-ip>:8001/health
```

## Get LangFuse keys

1. Open `http://<vps-ip>:3000` → create account
2. Settings → API Keys → Create new key
3. Copy public/secret keys into `.env`, then `docker compose restart agentbreaker`

## Demo flow

1. Open AgentBreaker UI
2. Enter Gemini key in sidebar (never leaves the server)
3. Click **Start mock vulnerable agent** (or it's already running)
4. Click **Index OWASP KB** (once)
5. Paste any public LLM-agent GitHub repo URL
6. Endpoint: `http://localhost:8001`
7. Click **Run Audit**
