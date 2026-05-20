"""Webhook API routes."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.common.webhooks import WebhookDeliveryService


router = APIRouter()


class RegisterWebhookEndpointRequest(BaseModel):
    workspace_id: str
    url: str
    signing_secret: Optional[str] = None
    enabled: bool = True
    verified: bool = False


class DisableWebhookEndpointRequest(BaseModel):
    workspace_id: str
    endpoint_id: str


class RotateWebhookEndpointRequest(BaseModel):
    workspace_id: str
    endpoint_id: str
    signing_secret: str


class RecordWebhookRequest(BaseModel):
    workspace_id: str
    endpoint_id: str
    event_id: str
    attempt: int = Field(default=1, ge=1)
    endpoint_version: Optional[int] = None
    payload: Any = None
    headers: Optional[Dict[str, Any]] = None
    response: Any = None
    failure: Any = None
    raw: Any = None
    private: Any = None
    internal: Any = None
    debug: Any = None
    trace: Any = None
    runtime: Any = None


def _get_webhook_service(request: Request) -> WebhookDeliveryService:
    service = getattr(request.app.state, "webhook_delivery_service", None)
    if service is None:
        raise HTTPException(
            status_code=500,
            detail="Webhook delivery service is not configured",
        )
    return service


@router.post("/webhooks/endpoints/register")
async def register_webhook_endpoint(
    request: Request,
    body: RegisterWebhookEndpointRequest,
):
    service = _get_webhook_service(request)
    try:
        endpoint = service.register_endpoint(
            workspace_id=body.workspace_id,
            url=body.url,
            signing_secret=body.signing_secret,
            enabled=body.enabled,
            verified=body.verified,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"endpoint": endpoint}


@router.post("/webhooks/endpoints/disable")
async def disable_webhook_endpoint(
    request: Request,
    body: DisableWebhookEndpointRequest,
):
    service = _get_webhook_service(request)
    endpoint = service.disable_endpoint(
        workspace_id=body.workspace_id,
        endpoint_id=body.endpoint_id,
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"endpoint": endpoint}


@router.post("/webhooks/endpoints/rotate")
async def rotate_webhook_endpoint(
    request: Request,
    body: RotateWebhookEndpointRequest,
):
    service = _get_webhook_service(request)
    endpoint = service.rotate_endpoint(
        workspace_id=body.workspace_id,
        endpoint_id=body.endpoint_id,
        signing_secret=body.signing_secret,
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"endpoint": endpoint}


@router.post("/webhooks/deliveries")
async def record_webhook_delivery(
    request: Request,
    body: RecordWebhookRequest,
):
    service = _get_webhook_service(request)
    record = service.record_delivery(**body.model_dump())
    return {"record": record}


@router.post("/webhooks/failures")
async def record_webhook_failure(request: Request, body: RecordWebhookRequest):
    service = _get_webhook_service(request)
    record = service.record_failure(**body.model_dump())
    return {"record": record}


@router.post("/webhooks/retries")
async def record_webhook_retry(request: Request, body: RecordWebhookRequest):
    service = _get_webhook_service(request)
    record = service.record_retry(**body.model_dump())
    return {"record": record}


@router.get("/webhooks/delivery-log")
async def get_webhook_delivery_log(
    request: Request,
    workspace_id: str,
    endpoint_id: Optional[str] = None,
    event_id: Optional[str] = None,
):
    service = _get_webhook_service(request)
    records = service.get_delivery_log(
        workspace_id=workspace_id,
        endpoint_id=endpoint_id,
        event_id=event_id,
    )
    return {"records": records}
