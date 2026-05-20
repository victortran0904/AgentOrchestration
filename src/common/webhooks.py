"""Webhook endpoint and delivery log management."""

from __future__ import annotations

import time
import uuid
from threading import RLock
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .redaction import sanitize_text, sanitize_value


_INTERNAL_ONLY_FIELDS = {
    "raw",
    "private",
    "internal",
    "debug",
    "trace",
    "runtime",
}


class WebhookDeliveryService:
    def __init__(self) -> None:
        self._lock = RLock()
        self._endpoints: Dict[str, Dict[str, Any]] = {}
        self._records: List[Dict[str, Any]] = []
        self._retry_records: Dict[str, Dict[str, Any]] = {}

    def register_endpoint(
        self,
        workspace_id: str,
        url: str,
        signing_secret: Optional[str] = None,
        enabled: bool = True,
        verified: bool = False,
    ) -> Dict[str, Any]:
        self._validate_url(url)
        now = time.time()
        endpoint = {
            "id": str(uuid.uuid4()),
            "workspace_id": workspace_id,
            "url": url,
            "signing_secret": signing_secret,
            "enabled": enabled,
            "verified": verified,
            "version": 1,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            self._endpoints[endpoint["id"]] = endpoint
            return self._public_endpoint(endpoint)

    def disable_endpoint(
        self,
        workspace_id: str,
        endpoint_id: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            endpoint = self._endpoints.get(endpoint_id)
            if endpoint is None or endpoint["workspace_id"] != workspace_id:
                return None
            endpoint["enabled"] = False
            endpoint["updated_at"] = time.time()
            return self._public_endpoint(endpoint)

    def rotate_endpoint(
        self, workspace_id: str, endpoint_id: str, signing_secret: str
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            endpoint = self._endpoints.get(endpoint_id)
            if endpoint is None or endpoint["workspace_id"] != workspace_id:
                return None
            endpoint["signing_secret"] = signing_secret
            endpoint["version"] += 1
            endpoint["updated_at"] = time.time()
            return self._public_endpoint(endpoint)

    def record_delivery(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int = 1,
        endpoint_version: Optional[int] = None,
        payload: Any = None,
        headers: Any = None,
        response: Any = None,
        failure: Any = None,
        raw: Any = None,
        private: Any = None,
        internal: Any = None,
        debug: Any = None,
        trace: Any = None,
        runtime: Any = None,
    ) -> Dict[str, Any]:
        return self._record(
            record_type="delivery",
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            endpoint_version=endpoint_version,
            payload=payload,
            headers=headers,
            response=response,
            failure=failure,
            raw=raw,
            private=private,
            internal=internal,
            debug=debug,
            trace=trace,
            runtime=runtime,
        )

    def record_failure(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int = 1,
        endpoint_version: Optional[int] = None,
        payload: Any = None,
        headers: Any = None,
        response: Any = None,
        failure: Any = None,
        raw: Any = None,
        private: Any = None,
        internal: Any = None,
        debug: Any = None,
        trace: Any = None,
        runtime: Any = None,
    ) -> Dict[str, Any]:
        return self._record(
            record_type="failure",
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            endpoint_version=endpoint_version,
            payload=payload,
            headers=headers,
            response=response,
            failure=failure,
            raw=raw,
            private=private,
            internal=internal,
            debug=debug,
            trace=trace,
            runtime=runtime,
        )

    def record_retry(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int = 1,
        endpoint_version: Optional[int] = None,
        payload: Any = None,
        headers: Any = None,
        response: Any = None,
        failure: Any = None,
        raw: Any = None,
        private: Any = None,
        internal: Any = None,
        debug: Any = None,
        trace: Any = None,
        runtime: Any = None,
    ) -> Dict[str, Any]:
        retry_key = self._retry_key(
            workspace_id,
            endpoint_id,
            event_id,
            attempt,
        )
        return self._record(
            record_type="retry",
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            endpoint_version=endpoint_version,
            payload=payload,
            headers=headers,
            response=response,
            failure=failure,
            raw=raw,
            private=private,
            internal=internal,
            debug=debug,
            trace=trace,
            runtime=runtime,
            retry_key=retry_key,
        )

    def get_delivery_log(
        self,
        workspace_id: str,
        endpoint_id: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            records = [
                record
                for record in self._records
                if record.get("workspace_id") == workspace_id
                and (
                    endpoint_id is None
                    or record.get("endpoint_id") == endpoint_id
                )
                and (event_id is None or record.get("event_id") == event_id)
            ]
        return [self._public_record(record) for record in records]

    def stored_records_snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._public_record(record) for record in self._records]

    def _record(
        self,
        record_type: str,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int,
        endpoint_version: Optional[int],
        payload: Any,
        headers: Any,
        response: Any,
        failure: Any,
        raw: Any,
        private: Any,
        internal: Any,
        debug: Any,
        trace: Any,
        runtime: Any,
        retry_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            if retry_key is not None:
                existing = self._retry_records.get(retry_key)
                if existing is not None:
                    return self._public_record(existing)

            endpoint, rejection_reason = self._resolve_endpoint_state(
                workspace_id=workspace_id,
                endpoint_id=endpoint_id,
                endpoint_version=endpoint_version,
            )
            record = {
                "id": str(uuid.uuid4()),
                "type": record_type,
                "workspace_id": workspace_id,
                "endpoint_id": endpoint_id,
                "event_id": event_id,
                "attempt": attempt,
                "endpoint_version": endpoint_version,
                "status": (
                    "accepted"
                    if rejection_reason is None
                    else "rejected"
                ),
                "rejection_reason": rejection_reason,
                "recorded_at": time.time(),
                "payload": payload,
                "headers": headers,
                "response": response,
                "failure": failure,
                "raw": raw,
                "private": private,
                "internal": internal,
                "debug": debug,
                "trace": trace,
                "runtime": runtime,
            }
            if endpoint is not None:
                record["current_endpoint_version"] = endpoint["version"]

            sanitized_record = self._public_record(record)
            self._records.append(sanitized_record)
            if retry_key is not None:
                self._retry_records[retry_key] = sanitized_record
            return self._public_record(sanitized_record)

    def _resolve_endpoint_state(
        self,
        workspace_id: str,
        endpoint_id: str,
        endpoint_version: Optional[int],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint is None:
            return None, "missing_endpoint"
        if endpoint["workspace_id"] != workspace_id:
            return endpoint, "workspace_mismatch"
        if not endpoint.get("enabled", True):
            return endpoint, "disabled"
        if not endpoint.get("verified", False):
            return endpoint, "unverified"
        if (
            endpoint_version is not None
            and endpoint_version != endpoint.get("version")
        ):
            return endpoint, "stale_endpoint_version"
        return endpoint, None

    def _validate_url(self, raw_url: str) -> None:
        parsed = urlsplit(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Webhook URL must be an absolute http/https URL")

    def _public_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": endpoint["id"],
            "workspace_id": endpoint["workspace_id"],
            "url": sanitize_text(endpoint["url"]),
            "enabled": endpoint["enabled"],
            "verified": endpoint["verified"],
            "version": endpoint["version"],
            "created_at": endpoint["created_at"],
            "updated_at": endpoint["updated_at"],
        }

    def _public_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        stripped = self._strip_internal_fields(record)
        return sanitize_value(stripped)

    def _strip_internal_fields(self, value: Any) -> Any:
        if isinstance(value, dict):
            cleaned: Dict[str, Any] = {}
            for key, item in value.items():
                if str(key).lower() in _INTERNAL_ONLY_FIELDS:
                    continue
                cleaned[key] = self._strip_internal_fields(item)
            return cleaned
        if isinstance(value, list):
            return [self._strip_internal_fields(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._strip_internal_fields(item) for item in value)
        if isinstance(value, set):
            return {self._strip_internal_fields(item) for item in value}
        return value

    def _retry_key(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int,
    ) -> str:
        return f"{workspace_id}:{endpoint_id}:{event_id}:{attempt}"
