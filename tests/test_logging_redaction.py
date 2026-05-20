import io
import json
import logging

from src.common.logging import StructuredFormatter
from src.common.redaction import REDACTED, sanitize_text, sanitize_value


def test_recursive_redaction_handles_nested_containers_and_sensitive_keys():
    sanitized = sanitize_value(
        {
            "password": "plain-password",
            "headers": {
                "Authorization": "Bearer auth-token",
                "Cookie": "session=value",
            },
            "items": [
                {"api_key": "api-secret"},
                ("safe", {"credential_id": "credential-secret"}),
            ],
            "signatures": {"webhook_signature": "signature-secret"},
            "seen": {"token=token-secret", "safe-value"},
            "safe": "visible",
        }
    )

    rendered = json.dumps(sanitized, default=list, sort_keys=True)
    assert "plain-password" not in rendered
    assert "auth-token" not in rendered
    assert "session=value" not in rendered
    assert "api-secret" not in rendered
    assert "credential-secret" not in rendered
    assert "signature-secret" not in rendered
    assert "token-secret" not in rendered
    assert sanitized["safe"] == "visible"
    assert sanitized["items"][0]["api_key"] == REDACTED
    assert isinstance(sanitized["items"][1], tuple)
    assert isinstance(sanitized["seen"], set)
    assert REDACTED in rendered


def test_sanitize_text_redacts_urls_and_free_text_secret_patterns():
    sanitized = sanitize_text(
        "POST https://user:pass@example.test/hook?"
        "token=query-secret&ok=1#frag Authorization: Bearer auth-token "
        "password: hunter2 api_key=api-secret "
        "credential=cred-secret sk-testsecret"
    )
    assert "user:pass" not in sanitized
    assert "[REDACTED]@example.test" not in sanitized
    assert "https://example.test/hook?token=[REDACTED]&ok=1" in sanitized
    assert "query-secret" not in sanitized
    assert "#frag" not in sanitized
    assert f"#{REDACTED}" not in sanitized
    assert "Bearer auth-token" not in sanitized
    assert "hunter2" not in sanitized
    assert "api-secret" not in sanitized
    assert "cred-secret" not in sanitized
    assert "sk-testsecret" not in sanitized
    assert "ok=1" in sanitized
    assert sanitized.count(REDACTED) >= 6


def test_structured_formatter_redacts_message_request_id_and_extra_fields():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(StructuredFormatter())
    logger = logging.getLogger("tests.logging.redaction")
    old_handlers = logger.handlers[:]
    old_level = logger.level
    old_propagate = logger.propagate
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logger.info(
            "delivery failed password=message-secret "
            "Bearer bearer-secret sk-testsecret",
            extra={
                "request_id": "request-token=request-secret",
                "api_key": "extra-secret",
                "payload": {
                    "refresh_token": "refresh-secret",
                    "safe": "visible",
                },
            },
        )
    finally:
        logger.handlers = old_handlers
        logger.setLevel(old_level)
        logger.propagate = old_propagate

    entry = json.loads(stream.getvalue())
    rendered = json.dumps(entry, sort_keys=True)
    assert "message-secret" not in rendered
    assert "bearer-secret" not in rendered
    assert "sk-testsecret" not in rendered
    assert "request-secret" not in rendered
    assert "extra-secret" not in rendered
    assert "refresh-secret" not in rendered
    assert entry["payload"]["safe"] == "visible"


def test_structured_formatter_redacts_exception_text():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(StructuredFormatter())
    logger = logging.getLogger("tests.logging.exception_redaction")
    old_handlers = logger.handlers[:]
    old_level = logger.level
    old_propagate = logger.propagate
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        try:
            raise RuntimeError("failed with token=exception-secret")
        except RuntimeError:
            logger.exception(
                "handler failed Authorization: Bearer message-secret"
            )
    finally:
        logger.handlers = old_handlers
        logger.setLevel(old_level)
        logger.propagate = old_propagate

    entry = json.loads(stream.getvalue())
    rendered = json.dumps(entry, sort_keys=True)
    assert "exception-secret" not in rendered
    assert "message-secret" not in rendered
    assert REDACTED in rendered
