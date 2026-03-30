"""PII Redaction Demo for AI Agent Telemetry.

Demonstrates a defense-in-depth approach to keeping PII out of
Azure Application Insights when instrumenting an AI agent with
OpenTelemetry.

Three layers of protection:
  1. enable_instrumentation(enable_sensitive_data=False)
     → stops the Agent Framework from recording message content in spans.
  2. Pluggable PII redaction (Presidio or Azure AI Language)
     → scrubs PII from any text before it is logged.
  3. PIILoggingFilter on every logger handler
     → intercepts ALL log records (including Azure SDK internals
       and OTel exporter logs) and redacts PII before export.

The LLM always sees the full, unredacted PII so it can respond
accurately.  Only the telemetry is scrubbed.

Usage:
    cp .env.sample .env     # fill in your values
    uv sync
    uv run python main.py
"""

import asyncio
import logging
import os
import threading
from typing import Annotated

from agent_framework import Agent, tool
from agent_framework.observability import create_resource, enable_instrumentation
from agent_framework.openai import OpenAIChatClient
from azure.identity import AzureCliCredential as SyncAzureCliCredential
from azure.identity.aio import AzureCliCredential, get_bearer_token_provider
from azure.monitor.opentelemetry import configure_azure_monitor
from dotenv import load_dotenv
from pydantic import Field
from rich import print
from rich.logging import RichHandler

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_handler = RichHandler(show_path=False, rich_tracebacks=True, show_level=False)
logging.basicConfig(level=logging.WARNING, handlers=[_handler], force=True, format="%(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

load_dotenv(override=True)

# ---------------------------------------------------------------------------
# PII Redaction — two pluggable approaches, selected by env var
#
#   PII_REDACTION_METHOD = "presidio"        → local, pattern-based
#   PII_REDACTION_METHOD = "azure_language"  → cloud, Azure AI Language
# ---------------------------------------------------------------------------

PII_REDACTION_METHOD = os.getenv("PII_REDACTION_METHOD", "presidio").lower()

# ---- Approach 1: Presidio (local, pattern-only) --------------------------
#
# Uses built-in pattern / checksum recognizers: EMAIL_ADDRESS, CREDIT_CARD,
# US_SSN, PHONE_NUMBER, IBAN_CODE, IP_ADDRESS, URL, DATE_TIME, CRYPTO, etc.
# PERSON / LOCATION detection is skipped (requires an NLP model).
# --------------------------------------------------------------------------

_presidio_analyzer = None
_presidio_anonymizer = None


def _init_presidio():
    """Lazy-init the Presidio analyzer + anonymizer (pattern-only, no spaCy)."""
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_anonymizer import AnonymizerEngine

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=["en"])
    registry.remove_recognizer("SpacyRecognizer")
    analyzer = AnalyzerEngine(registry=registry, supported_languages=["en"], nlp_engine=None)
    anonymizer = AnonymizerEngine()
    return analyzer, anonymizer


def redact_pii_presidio(text: str) -> str:
    """Redact PII using Presidio's local pattern-based recognizers."""
    global _presidio_analyzer, _presidio_anonymizer
    if _presidio_analyzer is None:
        _presidio_analyzer, _presidio_anonymizer = _init_presidio()

    results = _presidio_analyzer.analyze(text=text, language="en")
    if results:
        categories = {r.entity_type for r in results}
        logger.info(f"[Presidio] Detected {len(results)} PII entities: {categories}")
        anonymized = _presidio_anonymizer.anonymize(text=text, analyzer_results=results)
        return anonymized.text
    return text


# ---- Approach 2: Azure AI Language (cloud) --------------------------------

_language_client = None


def _init_azure_language():
    """Lazy-init the Azure AI Language TextAnalyticsClient."""
    from azure.ai.textanalytics import TextAnalyticsClient

    credential = SyncAzureCliCredential(process_timeout=30)
    return TextAnalyticsClient(
        endpoint=os.environ["AZURE_LANGUAGE_ENDPOINT"],
        credential=credential,
    )


def redact_pii_azure_language(text: str) -> str:
    """Call Azure AI Language PII detection and return the redacted text.

    Falls back to the original text if the service call fails.
    """
    global _language_client
    if _language_client is None:
        _language_client = _init_azure_language()

    try:
        documents = [{"id": "1", "text": text, "language": "en"}]
        response = _language_client.recognize_pii_entities(documents)
        
        if response and len(response) > 0:
            doc = response[0]
            if not doc.is_error and doc.entities:
                categories = {e.category for e in doc.entities}
                logger.info(f"[Azure Language] Detected {len(doc.entities)} PII entities: {categories}")
            return doc.redacted_text if hasattr(doc, 'redacted_text') else text
    except Exception as e:
        logger.warning(f"[Azure Language] Service call failed, returning original text: {e}")
    return text


# ---- Unified entry point --------------------------------------------------

# Thread-local guard to prevent infinite recursion:
#   redact_pii → _init_presidio → logger.warning → PIILoggingFilter → redact_pii …
_redact_guard = threading.local()


def redact_pii(text: str) -> str:
    """Redact PII from text using the configured method."""
    if not text or not text.strip():
        return text
    if getattr(_redact_guard, "active", False):
        return text  # break recursion cycle
    _redact_guard.active = True
    try:
        if PII_REDACTION_METHOD == "azure_language":
            return redact_pii_azure_language(text)
        return redact_pii_presidio(text)
    finally:
        _redact_guard.active = False


# ---------------------------------------------------------------------------
# PII Logging Filter — scrub PII from ALL log records before they are
# emitted (and exported to Application Insights via OTel).
# ---------------------------------------------------------------------------


class PIILoggingFilter(logging.Filter):
    """Logging filter that redacts PII from log messages before export."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg and isinstance(record.msg, str):
            record.msg = redact_pii(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_pii(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_pii(str(a)) if isinstance(a, str) else a for a in record.args
                )
        return True


# ---------------------------------------------------------------------------
# Telemetry setup
# ---------------------------------------------------------------------------

# Layer 1 — export traces/logs to Azure Application Insights
configure_azure_monitor(
    connection_string=os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"],
    resource=create_resource(),
    enable_live_metrics=True,
)

# Layer 2 — tell the Agent Framework NOT to record message content in spans
enable_instrumentation(enable_sensitive_data=False)

# Layer 3 — install PII filter on the root logger AND every handler
# (including the OTel LoggingHandler added by configure_azure_monitor)
_pii_filter = PIILoggingFilter()
logging.getLogger().addFilter(_pii_filter)
for h in logging.getLogger().handlers:
    h.addFilter(_pii_filter)

logger.info("Azure Application Insights export enabled")
logger.info(f"PII redaction method: {PII_REDACTION_METHOD}")

# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

API_HOST = os.getenv("API_HOST", "github")

async_credential = None
if API_HOST == "azure":
    async_credential = AzureCliCredential(process_timeout=60)
    token_provider = get_bearer_token_provider(async_credential, "https://cognitiveservices.azure.com/.default")
    client = OpenAIChatClient(
        base_url=f"{os.environ['AZURE_OPENAI_ENDPOINT']}/openai/v1/",
        api_key=token_provider,
        model_id=os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT"],
    )
elif API_HOST == "github":
    client = OpenAIChatClient(
        base_url="https://models.github.ai/inference",
        api_key=os.environ["GITHUB_TOKEN"],
        model_id=os.getenv("GITHUB_MODEL", "openai/gpt-4o-mini"),
    )
else:
    client = OpenAIChatClient(
        api_key=os.environ["OPENAI_API_KEY"],
        model_id=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    )

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool
def lookup_customer(
    name: Annotated[str, Field(description="Customer full name")],
    email: Annotated[str, Field(description="Customer email address")],
) -> dict:
    """Looks up a customer record by name and email."""
    logger.info(f"Looking up customer record for {name} ({email})")
    return {
        "name": name,
        "email": email,
        "phone": "+1-555-867-5309",
        "ssn_last4": "6789",
        "address": "742 Evergreen Terrace, Springfield, IL 62704",
        "date_of_birth": "1985-03-15",
        "account_number": "ACCT-2024-00042",
        "credit_card_last4": "4242",
    }


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

agent = Agent(
    name="pii-demo-agent",
    client=client,
    instructions=(
        "You are a helpful customer-service assistant that can look up customer records. "
        "When returning customer info, include all the details you have."
    ),
    tools=[lookup_customer],
)

# ---------------------------------------------------------------------------
# Test queries
# ---------------------------------------------------------------------------


async def main():
    # Query 1: User message contains PII directly
    print("[bold]--- Query 1: PII in user message ---[/bold]")
    response = await agent.run(
        "My name is John Smith, my email is john.smith@example.com, "
        "my SSN is 123-45-6789, and my credit card number is 4111-1111-1111-1111. "
        "Can you look up my customer record?"
    )
    print(response.text)

    # Query 2: Tool call that returns PII in its response
    print("\n[bold]--- Query 2: PII via tool call/response ---[/bold]")
    response = await agent.run(
        "Look up the customer record for Jane Doe with email jane.doe@contoso.com"
    )
    print(response.text)

    if async_credential:
        await async_credential.close()


if __name__ == "__main__":
    asyncio.run(main())