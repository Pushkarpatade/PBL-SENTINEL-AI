# AI-Powered Autonomous Cyber Defence & Incident Response

### SentinelAI — AI-Assisted Security Operations Prototype

![SentinelAI](https://img.shields.io/badge/Status-Prototype-orange) ![Python](https://img.shields.io/badge/Backend-FastAPI-blue) ![React](https://img.shields.io/badge/Frontend-React_18-cyan) ![AI](https://img.shields.io/badge/AI-LangGraph-purple)

**SentinelAI** is a defensive cybersecurity project prototype for ingesting security events, applying basic rules and heuristic anomaly checks, correlating alerts, and generating AI-assisted incident summaries for analyst review.

The repository demonstrates a BTech capstone architecture. It is not a production SOC or autonomous response platform. The production direction is to prioritize established tools—Suricata for network alerts and Wazuh for endpoint/SIEM alerts—and use SentinelAI for normalized cases, correlation, analyst workflow, and evidence-linked AI assistance. See the [industry-scale roadmap](docs/Industry_Scale_Roadmap.md) and [production integration plan](Implementation_Plan.md) for the target design, implementation gaps, and rollout phases.

---

## Architecture and current capabilities

### 1. Ingestion and detection

- **Custom Python IDS (raw sockets):** A Windows packet sensor prototype for local lab telemetry. It is not a replacement for a validated Suricata deployment.
- **API ingestion:** FastAPI adapters accept native Suricata EVE alerts and Wazuh manager alerts using separate shared ingest tokens. `suricata_shipper.py` forwards EVE alert records; `scripts/wazuh_integration.py` is a Wazuh Manager custom integration that must be installed/configured on your manager. These require real sensor deployments and are not configured just by running the dashboard.
- **Rules engine:** Basic deterministic checks for selected event types and patterns.
- **Heuristic anomaly detector:** The current detector uses simple thresholds and selected event labels; it is not a trained Isolation Forest and has not been validated against a labeled dataset.

### 2. AI-assisted investigation

The project includes LangGraph investigation and read-only chatbot workflows:

- The chatbot retrieves up to five recent incident records and linked Suricata/Wazuh alert metadata, then returns a plain-language summary. Without a Groq key, it produces a deterministic summary from stored data.
- With either a Groq or Gemini API key configured, the backend can ask the selected provider to summarize evidence. The model is an optional summarizer, not the detection authority.
- Optional Qdrant Cloud retrieval indexes approved Markdown runbooks and project guidance with local FastEmbed vectors; it does not index raw event payloads. Latest-five incident retrieval remains SQL-backed.
- VirusTotal and AbuseIPDB enrichment is optional, uses only public source IPs, and does not establish attribution or compromise.
- Threat-intelligence results are enrichment signals; they do not verify attribution or compromise.
- Source IP addresses are redacted before incident text is sent to Groq. Redaction is not encryption or a guarantee that all sensitive data has been removed.

### 3. Dashboard

The React dashboard provides a local interface for viewing prototype telemetry and incidents. Its client-side login is demo-only; the API and dashboard are not currently production-secured.

---

## Run locally

For real connector, API key, and `.env` setup, follow [Real Integrations Setup](docs/Real_Integrations_Setup.md). The steps cover Suricata, a real Wazuh Manager/Agent path, Groq or Gemini, Qdrant Cloud, threat-intelligence APIs, LangSmith, and optional PostgreSQL.

### Prerequisites

- Python version compatible with `backend/requirements.txt`
- Node.js and npm
- PostgreSQL if using the configured PostgreSQL database; otherwise check `backend/core/config.py` for the local SQLite default

### Start the backend

1. Open a terminal in `backend`.
2. Activate the existing Windows environment if present: `..\backend\venv\Scripts\activate` (from the repository root, run `backend\venv\Scripts\activate`).
3. Start from the `backend` directory: `python run_server.py` (reads `API_HOST` and `API_PORT` from `backend/.env`).
4. Local API documentation is at `http://127.0.0.1:8000/docs`.

### Start the frontend

1. Open a second terminal in `frontend`.
2. Run `npm run dev`.
3. Open the local Vite URL printed by the command (typically `http://localhost:5173`).

Do not treat mock/demo credentials or locally bound development endpoints as production authentication.

### Kali lab testing

Use only a disposable target inside an isolated host-only/internal virtual network. Follow the [isolated Kali testing guide](docs/Kali_Testing_Guide.md); it includes a low-rate scan limited to one known lab target and controlled event verification. Do not run scans against the broader LAN or real systems.

Synthetic event scripts submit fabricated JSON to test API plumbing; they do not perform live network tests.

---

## Response safety

Treat AI recommendations as analyst guidance only. Response execution is currently disabled in both the API and dashboard. Re-enable it only after authentication, authorization, explicit approval, target validation, auditing, and rollback safeguards are implemented.
