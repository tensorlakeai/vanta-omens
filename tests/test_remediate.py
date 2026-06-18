from vanta_omens.remediate import (
    CommandError,
    _agent_env,
    _authenticated_clone_url,
    _build_prompt,
    _github_owner_repo,
    _remediation_validation_errors,
    _remediation_title,
    _run,
    branch_suffix_from_request_id,
    remediation_branch_name,
)


def test_authenticated_clone_url_injects_github_token(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    assert (
        _authenticated_clone_url("https://github.com/acme/service.git")
        == "https://x-access-token:token-123@github.com/acme/service.git"
    )


def test_authenticated_clone_url_converts_git_ssh(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    assert (
        _authenticated_clone_url("git@github.com:acme/service.git")
        == "https://x-access-token:token-123@github.com/acme/service.git"
    )


def test_github_owner_repo() -> None:
    assert _github_owner_repo("https://github.com/acme/service.git") == ("acme", "service")
    assert _github_owner_repo("git@github.com:acme/service.git") == ("acme", "service")


def test_agent_env_sets_codex_api_key() -> None:
    env = _agent_env("gpt-4.1-mini", "openai-key")

    assert env["OPENAI_API_KEY"] == "openai-key"
    assert env["CODEX_API_KEY"] == "openai-key"
    assert env["OPENAI_MODEL"] == "gpt-4.1-mini"


def test_build_prompt_requires_matching_lockfile_updates() -> None:
    from vanta_omens.models import RepositoryWorkItem

    item = RepositoryWorkItem.model_validate(
        {
            "repository_key": "github.com/acme/service",
            "clone_url": "https://github.com/acme/service.git",
            "asset": {
                "id": "asset-1",
                "name": "acme/service",
                "assetType": "CODE_REPOSITORY",
            },
            "vulnerabilities": [
                {
                    "id": "vuln-1",
                    "name": "GHSA-1",
                    "packageIdentifier": "npm-example < 1.2.3",
                    "fixedVersion": "1.2.3",
                }
            ],
        }
    )

    prompt = _build_prompt(item)

    assert "package-manager lockfile" in prompt
    assert "already\nbelongs to that project" in prompt
    assert "Do not invent package-specific lockfiles" in prompt
    assert "npm-list.json" in prompt
    assert "only if they already exist in the repository\nand are intentionally tracked" in prompt
    assert "package-lock.json" in prompt
    assert "uv.lock" in prompt
    assert "Cargo.toml with the applicable\nCargo.lock" in prompt
    assert "single-package project" in prompt
    assert "go.sum" in prompt


def test_validation_rejects_new_package_lock_without_package_json(tmp_path) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"name":"repo","lockfileVersion":3,"requires":true,"packages":{}}\n',
        encoding="utf-8",
    )

    assert _remediation_validation_errors(tmp_path, {"package-lock.json": "??"}) == [
        "package-lock.json was created without package.json in the same directory"
    ]


def test_validation_allows_new_package_lock_with_package_json(tmp_path) -> None:
    (tmp_path / "package.json").write_text('{"name":"repo"}\n', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"name":"repo","lockfileVersion":3,"packages":{}}\n',
        encoding="utf-8",
    )

    assert _remediation_validation_errors(tmp_path, {"package-lock.json": "??"}) == []


def test_validation_rejects_new_dependency_report_files(tmp_path) -> None:
    (tmp_path / "npm-list.json").write_text("{}\n", encoding="utf-8")

    assert _remediation_validation_errors(tmp_path, {"npm-list.json": "??"}) == [
        "npm-list.json is a non-standard dependency report file"
    ]


def test_validation_allows_updates_to_existing_dependency_report_files(tmp_path) -> None:
    (tmp_path / "npm-list.json").write_text("{}\n", encoding="utf-8")

    assert _remediation_validation_errors(tmp_path, {"npm-list.json": " M"}) == []


def test_remediation_title_includes_run_date() -> None:
    from datetime import date

    assert _remediation_title(date(2026, 6, 18)) == "Fix Vanta-reported vulnerabilities (2026-06-18)"


def test_run_can_omit_stdout_from_command_error() -> None:
    try:
        _run(
            ["sh", "-c", "printf 'huge prompt'; printf 'codex error' >&2; exit 7"],
            include_stdout_on_error=False,
        )
    except CommandError as exc:
        assert exc.returncode == 7
        assert exc.stdout == ""
        assert "codex error" in exc.stderr
        assert "huge prompt" not in str(exc)
    else:
        raise AssertionError("expected CommandError")


def test_remediation_branch_name_includes_run_suffix() -> None:
    assert (
        remediation_branch_name(
            "github.com/acme/service.git",
            branch_suffix="dq2XwpP-XGPAQ4Tt_FPwG",
        )
        == "vanta/remediate-github-com-acme-service-git-dq2xwpp-xgpaq4tt-fpwg"
    )


def test_branch_suffix_from_request_id_uses_short_slug() -> None:
    assert branch_suffix_from_request_id("dq2XwpP-XGPAQ4Tt_FPwG") == "pp-xgpaq4tt-fpwg"
