# PII Redaction for AI Agent Telemetry

Defense-in-depth approach to keeping PII out of Azure Application Insights when instrumenting an AI agent with OpenTelemetry and [Microsoft Agent Framework](https://github.com/microsoft/agent-framework).

## The Problem

When you instrument an AI agent with OpenTelemetry and export traces to Azure Application Insights, **PII from conversations ends up in your telemetry** — prompt text, tool inputs/outputs, and LLM responses all get stored in the `traces` table with names, emails, SSNs, credit card numbers, etc.

## The Solution: Three Layers of Protection

```
┌─────────────────────────────────────────────────────┐
│  User  ──→  Agent (full PII)  ──→  LLM             │
│                    │                                 │
│                    ▼                                 │
│  Layer 1: enable_sensitive_data=False                │
│    └─ Stops recording message content in OTel spans  │
│                    │                                 │
│  Layer 2: redact_pii() via Presidio or Azure AI      │
│    └─ Scrubs PII from any text before logging        │
│                    │                                 │
│  Layer 3: PIILoggingFilter on all log handlers       │
│    └─ Intercepts ALL log records before export       │
│                    ▼                                 │
│         Azure Application Insights (clean)           │
└─────────────────────────────────────────────────────┘
```

> **Key design decision:** The LLM always sees the full PII so it can respond accurately. Only the *logs and telemetry* are scrubbed.

### Two Pluggable PII Redaction Approaches

| Approach | Env var value | Pros | Cons |
|---|---|---|---|
| **Presidio** (local) | `presidio` | Zero network calls, works offline, fast | Pattern-only — no PERSON/LOCATION detection |
| **Azure AI Language** (cloud) | `azure_language` | Full NLP — catches names, addresses, orgs | Requires network call + Azure resource |

Switch between them with a single environment variable:

```bash
PII_REDACTION_METHOD=presidio       # local, pattern-based
PII_REDACTION_METHOD=azure_language  # cloud, Azure AI Language
```

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Azure CLI authenticated (`az login`)
- Azure Application Insights resource
- *(Optional)* Azure AI Language / AIServices resource (for `azure_language` approach)
- An LLM backend: Azure OpenAI, OpenAI, or GitHub Models

## Quickstart

```bash
# Clone and enter the project
git clone https://github.com/YOUR-USERNAME/PII-Redaction.git
cd PII-Redaction

# Configure environment
cp .env.sample .env
# Edit .env with your values

# Install dependencies (choose one method)
# Method 1: Using pip (recommended)
pip install -r requirements.txt

# Method 2: Using uv (if you have it installed)
uv sync

# Run the demo
python main.py
```

## Environment Variables

See [`.env.sample`](.env.sample) for all available variables. The required ones depend on your setup:

| Variable | Required | Description |
|---|---|---|
| `API_HOST` | Yes | `azure`, `openai`, or `github` |
| `AZURE_OPENAI_ENDPOINT` | If azure | Azure OpenAI endpoint URL |
| `AZURE_OPENAI_CHAT_DEPLOYMENT` | If azure | Deployment name (e.g. `gpt-4o-mini`) |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Yes | App Insights connection string |
| `PII_REDACTION_METHOD` | No | `presidio` (default) or `azure_language` |
| `AZURE_LANGUAGE_ENDPOINT` | If azure_language | Azure AI Language endpoint |

## What It Tests

The demo runs two queries to exercise different PII scenarios:

1. **PII in user message** — name, email, SSN, and credit card sent directly in the prompt
2. **PII via tool response** — `lookup_customer` tool returns a full customer profile (phone, address, DOB, account number, etc.)

After running, check your Application Insights `traces` table to verify PII has been redacted.

## Interesting Implementation Details

- **Thread-local recursion guard** — Presidio initialization logs warnings, which triggers the PIILoggingFilter, which calls `redact_pii()`, which tries to init Presidio again → infinite recursion. Solved with a `threading.local()` re-entrancy guard.
- **Filter on handlers, not just loggers** — OTel's `LoggingHandler` captures `LogRecord` objects independently from the logger hierarchy, so the filter must be installed on every handler.
- **`azure-ai-textanalytics` v6 API** — Uses `TextAnalysisClient` (not `TextAnalyticsClient`) with the `analyze_text()` method and `logging_opt_out=True` to avoid sending PII to the Language service's own logs.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
