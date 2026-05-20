import json
import logging

from fastapi.testclient import TestClient

from src.api.server import create_app
from src.common.redaction import REDACTED
from src.common.webhooks import WebhookDeliveryService


def test_valid_records_are_sanitized_and_public_snapshot_has_no_raw_secrets():
    service = WebhookDeliveryService()
    endpoint = service.register_endpoint(
        workspace_id="ws-1",
        url="https://user:pass@example.test/hook?token=query-secret&ok=1",
        signing_secret="signing-secret",
        verified=True,
    )
    assert endpoint["url"] == "https://example.test/hook?token=[REDACTED]&ok=1"
    assert "signing_secret" not in endpoint

    record = service.record_failure(
        workspace_id="ws-1",
        endpoint_id=endpoint["id"],
        event_id="evt-1",
        endpoint_version=1,
        payload={
            "safe": "visible",
            "token": "payload-secret",
            "nested": {
                "debug": {"token": "nested-debug-secret"},
                "safe": "nested-visible",
            },
        },
        headers={"Authorization": "Bearer header-secret", "X-Trace-Id": "ok"},
        response={
            "status": 500,
            "body": "api_key=response-secret",
            "raw": {"content": "raw-secret"},
            "private": {"reason": "private-secret"},
            "runtime": {"latency_ms": 30},
        },
        failure={
            "message": "password=fail-secret",
            "internal": {"trace": "trace-secret"},
            "safe": "still-visible",
        },
        trace={"event": "trace-secret"},
    )

    rendered = json.dumps(record, sort_keys=True)
    assert "payload-secret" not in rendered
    assert "nested-debug-secret" not in rendered
    assert "header-secret" not in rendered
    assert "response-secret" not in rendered
    assert "raw-secret" not in rendered
    assert "private-secret" not in rendered
    assert "fail-secret" not in rendered
    assert "trace-secret" not in rendered
    assert record["headers"]["Authorization"] == REDACTED
    assert record["payload"]["safe"] == "visible"
    assert record["failure"]["safe"] == "still-visible"
    assert "raw" not in rendered
    assert "private" not in rendered
    assert "internal" not in rendered
    assert "debug" not in rendered
    assert "trace" not in rendered
    assert "runtime" not in rendered

    snapshot = json.dumps(
        service.get_delivery_log(workspace_id="ws-1"),
        sort_keys=True,
    )
    stored_snapshot = json.dumps(service._records, sort_keys=True)
    for persisted in (snapshot, stored_snapshot):
        assert "signing-secret" not in persisted
        assert "query-secret" not in persisted
        assert "user:pass" not in persisted
        assert "payload-secret" not in persisted
        assert "raw-secret" not in persisted
        assert "private-secret" not in persisted
        assert "trace-secret" not in persisted
        assert "raw" not in persisted
        assert "private" not in persisted
        assert "internal" not in persisted
        assert "debug" not in persisted
        assert "trace" not in persisted
        assert "runtime" not in persisted


def test_rejected_states_do_not_expose_owner_url_or_secrets():
    service = WebhookDeliveryService()
    owner_endpoint = service.register_endpoint(
        workspace_id="owner-ws",
        url="https://owner:pw@example.test/hook?token=owner-secret",
        signing_secret="owner-signing-secret",
        verified=True,
    )
    disabled_endpoint = service.register_endpoint(
        workspace_id="ws-disabled",
        url="https://disabled.example.test/hook?token=disabled-secret",
        verified=True,
    )
    service.disable_endpoint("ws-disabled", disabled_endpoint["id"])
    unverified_endpoint = service.register_endpoint(
        workspace_id="ws-unverified",
        url="https://unverified.example.test/hook?token=unverified-secret",
        verified=False,
    )
    rotating_endpoint = service.register_endpoint(
        workspace_id="ws-rotate",
        url="https://rotate.example.test/hook?token=rotate-secret",
        signing_secret="rotate-secret",
        verified=True,
    )
    service.rotate_endpoint(
        "ws-rotate",
        rotating_endpoint["id"],
        "rotate-secret-v2",
    )

    missing = service.record_delivery(
        workspace_id="owner-ws",
        endpoint_id="missing",
        event_id="evt-missing",
        endpoint_version=1,
    )
    mismatch = service.record_delivery(
        workspace_id="other-ws",
        endpoint_id=owner_endpoint["id"],
        event_id="evt-mismatch",
        endpoint_version=1,
    )
    disabled = service.record_delivery(
        workspace_id="ws-disabled",
        endpoint_id=disabled_endpoint["id"],
        event_id="evt-disabled",
        endpoint_version=1,
    )
    unverified = service.record_delivery(
        workspace_id="ws-unverified",
        endpoint_id=unverified_endpoint["id"],
        event_id="evt-unverified",
        endpoint_version=1,
    )
    stale = service.record_delivery(
        workspace_id="ws-rotate",
        endpoint_id=rotating_endpoint["id"],
        event_id="evt-stale",
        endpoint_version=1,
    )

    assert missing["status"] == "rejected"
    assert missing["rejection_reason"] == "missing_endpoint"
    assert mismatch["rejection_reason"] == "workspace_mismatch"
    assert disabled["rejection_reason"] == "disabled"
    assert unverified["rejection_reason"] == "unverified"
    assert stale["rejection_reason"] == "stale_endpoint_version"

    rejected_snapshot = json.dumps(
        [missing, mismatch, disabled, unverified, stale],
        sort_keys=True,
    )
    assert "owner-secret" not in rejected_snapshot
    assert "owner-signing-secret" not in rejected_snapshot
    assert "disabled-secret" not in rejected_snapshot
    assert "unverified-secret" not in rejected_snapshot
    assert "rotate-secret" not in rejected_snapshot
    assert "owner:pw" not in rejected_snapshot
    assert "signing_secret" not in rejected_snapshot


def test_retry_idempotency_preserves_first_sanitized_record():
    service = WebhookDeliveryService()
    endpoint = service.register_endpoint(
        workspace_id="ws-retry",
        url="https://retry.example.test/hook",
        verified=True,
    )

    first = service.record_retry(
        workspace_id="ws-retry",
        endpoint_id=endpoint["id"],
        event_id="evt-retry",
        attempt=2,
        endpoint_version=1,
        payload={"token": "first-secret"},
        headers={"Authorization": "Bearer first-auth-secret"},
    )
    second = service.record_retry(
        workspace_id="ws-retry",
        endpoint_id=endpoint["id"],
        event_id="evt-retry",
        attempt=2,
        endpoint_version=1,
        payload={"token": "second-secret"},
        headers={"Authorization": "Bearer second-auth-secret"},
    )

    assert first == second
    records = service.get_delivery_log(
        workspace_id="ws-retry",
        endpoint_id=endpoint["id"],
        event_id="evt-retry",
    )
    assert len(records) == 1
    assert records[0]["payload"]["token"] == REDACTED
    assert records[0]["headers"]["Authorization"] == REDACTED
    retry_snapshot = json.dumps(records, sort_keys=True)
    assert "second-secret" not in retry_snapshot
    assert "second-auth-secret" not in retry_snapshot


def test_api_routes_use_app_isolated_service_state_and_sanitized_responses():
    app_one = create_app()
    app_two = create_app()
    client_one = TestClient(app_one)
    client_two = TestClient(app_two)
    headers = {"Authorization": "Bearer api-token"}

    register_response = client_one.post(
        "/api/v2/webhooks/endpoints/register",
        headers=headers,
        json={
            "workspace_id": "api-ws",
            "url": (
                "https://user:pass@example.test/hook?"
                "token=api-secret&ok=1"
            ),
            "signing_secret": "api-signing-secret",
            "verified": True,
        },
    )
    assert register_response.status_code == 200
    endpoint = register_response.json()["endpoint"]
    assert "signing_secret" not in endpoint
    assert endpoint["url"] == "https://example.test/hook?token=[REDACTED]&ok=1"

    delivery_response = client_one.post(
        "/api/v2/webhooks/deliveries",
        headers=headers,
        json={
            "workspace_id": "api-ws",
            "endpoint_id": endpoint["id"],
            "event_id": "api-evt-1",
            "attempt": 1,
            "endpoint_version": 1,
            "payload": {"token": "payload-secret", "safe": "ok"},
            "headers": {"Authorization": "Bearer auth-secret"},
            "response": {
                "runtime": {"ms": 20},
                "body": "token=response-secret",
            },
        },
    )
    assert delivery_response.status_code == 200
    record = delivery_response.json()["record"]
    assert record["payload"]["token"] == REDACTED
    assert record["headers"]["Authorization"] == REDACTED
    assert "runtime" not in json.dumps(record, sort_keys=True)

    app_one_log = client_one.get(
        "/api/v2/webhooks/delivery-log?"
        f"workspace_id=api-ws&endpoint_id={endpoint['id']}",
        headers=headers,
    )
    assert app_one_log.status_code == 200
    assert len(app_one_log.json()["records"]) == 1

    app_two_log = client_two.get(
        "/api/v2/webhooks/delivery-log?"
        f"workspace_id=api-ws&endpoint_id={endpoint['id']}",
        headers=headers,
    )
    assert app_two_log.status_code == 200
    assert app_two_log.json()["records"] == []


def test_logging_middleware_redacts_query_params(caplog):
    app = create_app()
    client = TestClient(app)
    headers = {"Authorization": "Bearer middleware-token"}

    caplog.set_level(logging.INFO, logger="src.api.middleware")
    response = client.get(
        "/api/v2/webhooks/delivery-log?workspace_id=ws-log&token=query-secret",
        headers=headers,
    )
    assert response.status_code == 200

    messages = [
        record.getMessage()
        for record in caplog.records
        if record.name == "src.api.middleware"
    ]
    log_line = next(
        message
        for message in messages
        if "/api/v2/webhooks/delivery-log" in message
    )
    assert "query-secret" not in log_line
    assert "token=[REDACTED]" in log_line
