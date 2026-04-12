import logging
import os
import sys

import structlog
from langfuse import Langfuse


def setup_logging(log_file: str = "./logs/agentbreaker.jsonl", level: str = "INFO"):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.WriteLoggerFactory(
            file=open(log_file, "a", buffering=1)
        ),
    )


def get_logger():
    return structlog.get_logger()


_langfuse_client: Langfuse | None = None


def get_langfuse() -> Langfuse | None:
    global _langfuse_client
    if _langfuse_client is not None:
        return _langfuse_client

    public_key = os.getenv("LANGFUSE_PUBLIC_KEY", "")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY", "")
    host = os.getenv("LANGFUSE_HOST", "http://localhost:3000")

    if not public_key or not secret_key:
        return None

    try:
        _langfuse_client = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host,
        )
        return _langfuse_client
    except Exception:
        return None
