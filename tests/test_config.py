from vanta_omens.config import VantaSettings


def test_vanta_asset_fetch_concurrency_default(monkeypatch) -> None:
    monkeypatch.setenv("VANTA_CLIENT_ID", "client-id")
    monkeypatch.setenv("VANTA_CLIENT_SECRET", "client-secret")
    monkeypatch.delenv("VANTA_ASSET_FETCH_CONCURRENCY", raising=False)

    assert VantaSettings.from_env().vanta_asset_fetch_concurrency == 10


def test_vanta_asset_fetch_concurrency_override(monkeypatch) -> None:
    monkeypatch.setenv("VANTA_CLIENT_ID", "client-id")
    monkeypatch.setenv("VANTA_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("VANTA_ASSET_FETCH_CONCURRENCY", "25")

    assert VantaSettings.from_env().vanta_asset_fetch_concurrency == 25


def test_vanta_settings_strip_secret_whitespace(monkeypatch) -> None:
    monkeypatch.setenv("VANTA_CLIENT_ID", " client-id\n")
    monkeypatch.setenv("VANTA_CLIENT_SECRET", " client-secret\n")
    monkeypatch.setenv("VANTA_SCOPE", " vanta-api.all:read\n")
    monkeypatch.setenv("VANTA_BASE_URL", " https://api.vanta.com/\n")

    settings = VantaSettings.from_env()

    assert settings.vanta_client_id == "client-id"
    assert settings.vanta_client_secret == "client-secret"
    assert settings.vanta_scope == "vanta-api.all:read"
    assert settings.vanta_base_url == "https://api.vanta.com"
