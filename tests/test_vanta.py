import asyncio

import httpx

from vanta_omens.models import Vulnerability
from vanta_omens.vanta import VantaClient, gather_code_repository_assets


def test_async_vanta_client_paginates_and_reuses_token() -> None:
    token_requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_requests
        if request.url.path == "/oauth/token":
            token_requests += 1
            return httpx.Response(200, json={"access_token": "token-1", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer token-1"
        assert request.url.path == "/v1/vulnerabilities"
        if "pageCursor=next" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "results": {
                        "data": [{"id": "vuln-2", "name": "CVE-2", "targetId": "asset-2"}],
                        "pageInfo": {"hasNextPage": False},
                    }
                },
            )
        return httpx.Response(
            200,
            json={
                "results": {
                    "data": [{"id": "vuln-1", "name": "CVE-1", "targetId": "asset-1"}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "next"},
                }
            },
        )

    async def run() -> None:
        async with _client(handler) as client:
            vulnerabilities = await client.list_open_fixable_vulnerabilities()
        assert [vuln.id for vuln in vulnerabilities] == ["vuln-1", "vuln-2"]
        assert token_requests == 1

    asyncio.run(run())


def test_gather_code_repository_assets_filters_non_repo_assets() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "token-1", "expires_in": 3600})
        asset_id = request.url.path.rsplit("/", 1)[-1]
        asset_type = "CODE_REPOSITORY" if asset_id == "asset-1" else "SERVER"
        return httpx.Response(
            200,
            json={
                "id": asset_id,
                "name": asset_id,
                "assetType": asset_type,
                "scanners": [],
            },
        )

    async def run() -> None:
        async with _client(handler) as client:
            vulnerabilities = [
                _vulnerability("vuln-1", "asset-1"),
                _vulnerability("vuln-2", "asset-2"),
                _vulnerability("vuln-3", "asset-1"),
            ]
            assets = await gather_code_repository_assets(client, vulnerabilities)
        assert list(assets) == ["asset-1"]
        assert assets["asset-1"].asset_type == "CODE_REPOSITORY"

    asyncio.run(run())


def test_vanta_oauth_error_includes_sanitized_response_body() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": "invalid_scope",
                "message": "scope is invalid",
                "access_token": "secret-token",
            },
        )

    async def run() -> None:
        async with _client(handler) as client:
            try:
                await client.list_open_fixable_vulnerabilities()
            except RuntimeError as exc:
                message = str(exc)
            else:
                raise AssertionError("expected RuntimeError")

        assert "status=400" in message
        assert "invalid_scope" in message
        assert "scope is invalid" in message
        assert "secret-token" not in message

    asyncio.run(run())


def _client(handler) -> VantaClient:
    return VantaClient(
        base_url="https://api.vanta.test",
        client_id="client-id",
        client_secret="client-secret",
        scope="scope",
        transport=httpx.MockTransport(handler),
    )


def _vulnerability(vulnerability_id: str, target_id: str) -> Vulnerability:
    return Vulnerability.model_validate(
        {"id": vulnerability_id, "name": vulnerability_id, "targetId": target_id}
    )
