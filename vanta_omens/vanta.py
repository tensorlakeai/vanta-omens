from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
from tensorlake.applications import Logger

from vanta_omens.models import Vulnerability, VulnerableAsset

logger = Logger.get_logger(module="vanta_omens.vanta")


class VantaClient:
    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        scope: str,
        page_size: int = 100,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.page_size = page_size
        self.transport = transport
        self._token: str | None = None
        self._expires_at = 0.0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "VantaClient":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=60,
            transport=self.transport,
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._client:
            await self._client.aclose()
        self._client = None

    async def list_open_fixable_vulnerabilities(self) -> list[Vulnerability]:
        logger.info("Listing open fixable Vanta vulnerabilities", status="vanta_list_started")
        payloads = await self._paginate(
            "/v1/vulnerabilities",
            params={"isDeactivated": "false", "isFixAvailable": "true"},
        )
        logger.info(
            "Listed open fixable Vanta vulnerabilities",
            status="vanta_list_completed",
            vulnerability_count=len(payloads),
        )
        return [Vulnerability.model_validate(item) for item in payloads]

    async def get_vulnerable_asset(self, asset_id: str) -> VulnerableAsset:
        data = (await self._request("GET", f"/v1/vulnerable-assets/{asset_id}")).json()
        return VulnerableAsset.model_validate(data)

    async def _paginate(self, path: str, params: dict[str, str]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            page_params = dict(params)
            page_params["pageSize"] = str(self.page_size)
            if cursor:
                page_params["pageCursor"] = cursor
            data = (await self._request("GET", path, params=page_params)).json()
            results = data.get("results", {})
            page_items = results.get("data", [])
            items.extend(page_items)
            page_info = results.get("pageInfo", {})
            logger.info(
                "Fetched Vanta page",
                status="vanta_page_fetched",
                path=path,
                page_item_count=len(page_items),
                total_item_count=len(items),
                has_next_page=bool(page_info.get("hasNextPage")),
            )
            if not page_info.get("hasNextPage"):
                return items
            cursor = page_info.get("endCursor")
            if not cursor:
                return items

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        token = await self._access_token()
        response = await self._http.request(
            method,
            path,
            headers={"Authorization": f"Bearer {token}", **kwargs.pop("headers", {})},
            **kwargs,
        )
        response.raise_for_status()
        return response

    async def _access_token(self) -> str:
        if self._token and time.time() < self._expires_at - 60:
            return self._token
        response = await self._http.post(
            "/oauth/token",
            json={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scope,
                "grant_type": "client_credentials",
            },
            headers={"Content-Type": "application/json"},
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                "Vanta OAuth token request failed "
                f"status={response.status_code} body={_safe_response_body(response)}"
            ) from exc
        data = response.json()
        self._token = data["access_token"]
        self._expires_at = time.time() + int(data.get("expires_in", 3600))
        return self._token

    @property
    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=60,
                transport=self.transport,
            )
        return self._client


async def gather_code_repository_assets(
    client: VantaClient,
    vulnerabilities: list[Vulnerability],
    *,
    concurrency: int = 10,
) -> dict[str, VulnerableAsset]:
    target_ids = sorted({vuln.target_id for vuln in vulnerabilities if vuln.target_id})
    logger.info(
        "Fetching Vanta vulnerable assets",
        status="vanta_asset_fetch_started",
        target_count=len(target_ids),
        concurrency=concurrency,
    )
    semaphore = asyncio.Semaphore(concurrency)

    async def load(target_id: str) -> tuple[str, VulnerableAsset | None]:
        try:
            async with semaphore:
                asset = await client.get_vulnerable_asset(target_id)
        except Exception as exc:
            logger.warning(
                "Failed to fetch Vanta vulnerable asset",
                status="vanta_asset_fetch_failed",
                target_id=target_id,
                error=str(exc),
            )
            return target_id, None
        if asset.asset_type != "CODE_REPOSITORY":
            logger.debug(
                "Skipping non-source-control Vanta asset",
                status="vanta_asset_skipped",
                target_id=target_id,
                asset_type=asset.asset_type,
            )
            return target_id, None
        return target_id, asset

    pairs = await asyncio.gather(*(load(target_id) for target_id in target_ids))
    assets = {target_id: asset for target_id, asset in pairs if asset is not None}
    logger.info(
        "Fetched Vanta source repository assets",
        status="vanta_asset_fetch_completed",
        target_count=len(target_ids),
        code_repository_asset_count=len(assets),
    )
    return assets


def _safe_response_body(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        text = response.text
        return text[:500]
    if isinstance(body, dict):
        redacted = {
            key: ("***" if "secret" in key.lower() or "token" in key.lower() else value)
            for key, value in body.items()
        }
        return str(redacted)[:500]
    return str(body)[:500]
