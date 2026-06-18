from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import subprocess
import tempfile
from datetime import date
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx

from vanta_omens.models import RemediationResult, RepositoryWorkItem

_LOCKFILE_MANIFESTS = {
    "package-lock.json": "package.json",
    "npm-shrinkwrap.json": "package.json",
    "yarn.lock": "package.json",
    "pnpm-lock.yaml": "package.json",
    "bun.lock": "package.json",
    "bun.lockb": "package.json",
    "Cargo.lock": "Cargo.toml",
    "go.sum": "go.mod",
    "Gemfile.lock": "Gemfile",
    "composer.lock": "composer.json",
    "uv.lock": "pyproject.toml",
    "poetry.lock": "pyproject.toml",
    "Pipfile.lock": "Pipfile",
}

_STANDARD_LOCKFILE_NAMES = set(_LOCKFILE_MANIFESTS)

_NON_STANDARD_DEPENDENCY_ARTIFACTS = {
    "npm-list.json",
    "npm-audit.json",
    "yarn-list.json",
    "pnpm-list.json",
    "cargo-tree.txt",
    "pip-freeze.txt",
}


class CommandError(RuntimeError):
    def __init__(
        self,
        *,
        command: list[str],
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> None:
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command failed: {_display_command(command)} exit_code={returncode}")


def remediate_repository(
    item: RepositoryWorkItem,
    *,
    model: str,
    command_template: str,
    dry_run: bool,
    branch_suffix: str | None = None,
    logger=None,
) -> RemediationResult:
    branch = remediation_branch_name(item.repository_key, branch_suffix=branch_suffix)
    try:
        with tempfile.TemporaryDirectory(prefix="vanta-omens-") as temp_dir:
            repo_dir = Path(temp_dir) / "repo"
            clone_url = _authenticated_clone_url(item.clone_url)
            _log(logger, "Cloning repository", status="cloning", branch=branch)
            _run(["git", "clone", clone_url, str(repo_dir)])
            _run(["git", "remote", "set-url", "origin", clone_url], cwd=repo_dir)
            _run(["git", "checkout", "-B", branch], cwd=repo_dir)
            _log(logger, "Repository cloned", status="cloned", branch=branch)

            prompt_file = repo_dir / ".vanta-remediation-prompt.md"
            prompt_file.write_text(_build_prompt(item), encoding="utf-8")
            _log(
                logger,
                "Running remediation agent",
                status="running_agent",
                model=model,
                vulnerability_count=len(item.vulnerabilities),
            )
            _run_agent(command_template, model=model, prompt_file=prompt_file, cwd=repo_dir, logger=logger)
            prompt_file.unlink(missing_ok=True)
            _log(logger, "Remediation agent finished", status="agent_finished")

            changed_file_statuses = _changed_file_statuses(repo_dir)
            changed_files = list(changed_file_statuses)
            if not changed_files:
                _log(logger, "No repository changes detected", status="no_changes")
                return RemediationResult(
                    repository_key=item.repository_key,
                    clone_url=item.clone_url,
                    status="no_changes",
                    branch=branch,
                )

            validation_errors = _remediation_validation_errors(repo_dir, changed_file_statuses)
            if validation_errors:
                error = "Invalid remediation changes: " + "; ".join(validation_errors)
                _log(
                    logger,
                    "Repository remediation produced invalid changes",
                    level="error",
                    status="invalid_changes",
                    changed_file_count=len(changed_files),
                    validation_errors=validation_errors,
                )
                return RemediationResult(
                    repository_key=item.repository_key,
                    clone_url=item.clone_url,
                    status="failed",
                    branch=branch,
                    changed_files=changed_files,
                    error=error,
                )

            if dry_run:
                _log(
                    logger,
                    "Dry run complete with repository changes",
                    status="dry_run_changes",
                    changed_file_count=len(changed_files),
                )
                return RemediationResult(
                    repository_key=item.repository_key,
                    clone_url=item.clone_url,
                    status="dry_run_changes",
                    branch=branch,
                    changed_files=changed_files,
                )

            _log(logger, "Committing remediation changes", status="committing", changed_file_count=len(changed_files))
            title = _remediation_title()
            _run(["git", "add", "--all"], cwd=repo_dir)
            _run(["git", "commit", "-m", title], cwd=repo_dir)
            _log(logger, "Pushing remediation branch", status="pushing", branch=branch)
            _run(["git", "push", "--set-upstream", "origin", branch, "--force-with-lease"], cwd=repo_dir)
            _log(logger, "Creating pull request", status="creating_pull_request", branch=branch)
            pr_url = _create_pull_request(repo_dir, item, branch, title=title)
            _log(logger, "Pull request created", status="pull_request_created", pull_request_url=pr_url)
            return RemediationResult(
                repository_key=item.repository_key,
                clone_url=item.clone_url,
                status="pull_request_created",
                branch=branch,
                pull_request_url=pr_url,
                changed_files=changed_files,
            )
    except CommandError as exc:
        _log(
            logger,
            "Repository remediation command failed",
            level="error",
            status="failed",
            command=_display_command(exc.command),
            exit_code=exc.returncode,
            stdout_tail=_tail_lines(exc.stdout, max_chars=1200),
            stderr_tail=_tail_lines(exc.stderr, max_chars=4000),
        )
        error = str(exc)
        return RemediationResult(
            repository_key=item.repository_key,
            clone_url=item.clone_url,
            status="failed",
            branch=branch,
            error=error,
        )
    except Exception as exc:
        error = _single_line(str(exc), max_chars=1000)
        _log(logger, "Repository remediation raised an exception", level="error", status="failed", error=error)
        return RemediationResult(
            repository_key=item.repository_key,
            clone_url=item.clone_url,
            status="failed",
            branch=branch,
            error=error,
        )


def _run_agent(command_template: str, *, model: str, prompt_file: Path, cwd: Path, logger=None) -> None:
    openai_api_key = _openai_api_key()
    if not openai_api_key:
        raise RuntimeError("OPENAI_API_KEY secret is not available to the remediation worker")
    command = command_template.format(
        model=shlex.quote(model),
        prompt_file=shlex.quote(str(prompt_file)),
    )
    _log(
        logger,
        "Starting Codex remediation command",
        status="starting_agent_command",
        model=model,
        has_openai_api_key=True,
        has_codex_api_key=True,
    )
    _run(
        ["sh", "-c", command],
        cwd=cwd,
        extra_env=_agent_env(model, openai_api_key),
        include_stdout_on_error=False,
    )


def _agent_env(model: str, openai_api_key: str) -> dict[str, str]:
    return {
        "CODE_AGENT_MODEL": model,
        "CODEX_API_KEY": openai_api_key,
        "OPENAI_API_KEY": openai_api_key,
        "OPENAI_MODEL": model,
    }


def _build_prompt(item: RepositoryWorkItem) -> str:
    vulnerabilities = [
        vuln.model_dump(by_alias=True, exclude_none=True)
        for vuln in item.vulnerabilities
    ]
    return f"""You are fixing security vulnerabilities reported by Vanta.

Repository: {item.repository_key}
Source asset: {item.asset.name} ({item.asset.id})

Vulnerabilities:
```json
{json.dumps(vulnerabilities, indent=2, sort_keys=True)}
```

Apply the smallest correct dependency or code changes needed to remediate these findings.
Prefer package upgrades to broad refactors.

If you update any dependency manifest, update the package-manager lockfile that already
belongs to that project, or regenerate the standard lockfile with that project's package
manager. Do not invent package-specific lockfiles or create new ad hoc dependency
metadata, inventory, report, or audit files such as <package-name>.lock, npm-list.json,
npm-audit.json, yarn-list.json, pnpm-list.json, cargo-tree.txt, or pip-freeze.txt. You
may update those kinds of non-standard files only if they already exist in the repository
and are intentionally tracked.

Common manifest and lockfile pairs include package.json with package-lock.json,
npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, or bun.lockb; pyproject.toml,
setup.py, setup.cfg, requirements*.txt, or Pipfile with uv.lock, poetry.lock,
Pipfile.lock, or a project-defined requirements lockfile; Cargo.toml with the applicable
Cargo.lock, usually at the workspace root when there is a workspace and next to Cargo.toml
for a single-package project; go.mod with go.sum; Gemfile with Gemfile.lock; composer.json with
composer.lock; and pom.xml, build.gradle, or build.gradle.kts with the standard lockfiles
or wrapper-managed dependency metadata used by that project. Do not leave manifest and
lockfile versions inconsistent.

Run the relevant package manager tests, lockfile updates, and vulnerability checks when
available. Leave the repository in a reviewable state.
Do not commit, push, or open a pull request; the workflow handles that after your changes.
"""


def _changed_files(repo_dir: Path) -> list[str]:
    return list(_changed_file_statuses(repo_dir))


def _changed_file_statuses(repo_dir: Path) -> dict[str, str]:
    result = _run(["git", "status", "--porcelain"], cwd=repo_dir)
    files: dict[str, str] = {}
    for line in result.stdout.splitlines():
        status = line[:2]
        path = line[3:] if len(line) > 3 else line
        if " -> " in path:
            path = path.rsplit(" -> ", 1)[1]
        if path:
            files[path] = status
    return files


def _remediation_validation_errors(repo_dir: Path, changed_file_statuses: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for path, status in changed_file_statuses.items():
        if not _is_new_file_status(status):
            continue
        relative_path = Path(path)
        name = relative_path.name

        if name in _NON_STANDARD_DEPENDENCY_ARTIFACTS:
            errors.append(f"{path} is a non-standard dependency report file")
            continue

        if name.endswith(".lock") and name not in _STANDARD_LOCKFILE_NAMES:
            errors.append(f"{path} is not a standard package-manager lockfile")
            continue

        manifest_name = _LOCKFILE_MANIFESTS.get(name)
        if manifest_name and not (repo_dir / relative_path.parent / manifest_name).exists():
            errors.append(f"{path} was created without {manifest_name} in the same directory")
    return errors


def _is_new_file_status(status: str) -> bool:
    return "A" in status or "?" in status


def _remediation_title(today: date | None = None) -> str:
    run_date = today or date.today()
    return f"Fix Vanta-reported vulnerabilities ({run_date.isoformat()})"


def _create_pull_request(repo_dir: Path, item: RepositoryWorkItem, branch: str, *, title: str) -> str:
    owner, repo = _github_owner_repo(item.clone_url)
    base_branch = _default_branch(repo_dir)
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN or GH_TOKEN is required to create pull requests")
    response = httpx.post(
        f"https://api.github.com/repos/{owner}/{repo}/pulls",
        json={
            "title": title,
            "body": _pull_request_body(item),
            "head": branch,
            "base": base_branch,
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=60,
    )
    if response.status_code == 422:
        existing = _find_existing_pull_request(owner, repo, branch, token)
        if existing:
            return existing
    response.raise_for_status()
    return response.json()["html_url"]


def _pull_request_body(item: RepositoryWorkItem) -> str:
    lines = [
        "Automated remediation for Vanta-reported source repository vulnerabilities.",
        "",
        "Vulnerabilities:",
    ]
    for vuln in item.vulnerabilities:
        package = f" package={vuln.package_identifier}" if vuln.package_identifier else ""
        fixed = f" fixedVersion={vuln.fixed_version}" if vuln.fixed_version else ""
        lines.append(f"- {vuln.name} ({vuln.id}) severity={vuln.severity}{package}{fixed}")
    lines.extend(["", "Please review the generated changes and CI results before merging."])
    return "\n".join(lines)


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
    include_stdout_on_error: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=3600,
    )
    if result.returncode != 0:
        raise CommandError(
            command=command,
            returncode=result.returncode,
            stdout=_mask_secrets(result.stdout) if include_stdout_on_error else "",
            stderr=_mask_secrets(result.stderr),
        )
    return result


def _authenticated_clone_url(clone_url: str) -> str:
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token or "github.com" not in clone_url:
        return clone_url
    https_url = clone_url
    if clone_url.startswith("git@github.com:"):
        https_url = "https://github.com/" + clone_url.removeprefix("git@github.com:")
    parsed = urlparse(https_url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        return clone_url
    netloc = f"x-access-token:{token}@github.com"
    return urlunparse(parsed._replace(netloc=netloc))


def _github_owner_repo(clone_url: str) -> tuple[str, str]:
    https_url = clone_url
    if clone_url.startswith("git@github.com:"):
        https_url = "https://github.com/" + clone_url.removeprefix("git@github.com:")
    parsed = urlparse(https_url)
    if parsed.hostname != "github.com":
        raise RuntimeError("Pull request creation currently supports GitHub repository URLs")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise RuntimeError(f"Could not parse GitHub owner/repo from {clone_url}")
    return parts[0], parts[1].removesuffix(".git")


def _default_branch(repo_dir: Path) -> str:
    result = _run(["git", "remote", "show", "origin"], cwd=repo_dir)
    match = re.search(r"HEAD branch: (.+)", result.stdout)
    return match.group(1).strip() if match else "main"


def _find_existing_pull_request(owner: str, repo: str, branch: str, token: str) -> str | None:
    response = httpx.get(
        f"https://api.github.com/repos/{owner}/{repo}/pulls",
        params={"head": f"{owner}:{branch}", "state": "open"},
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=60,
    )
    response.raise_for_status()
    pulls = response.json()
    if pulls:
        return pulls[0].get("html_url")
    return None


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value.lower()).strip("-")[:80]


def remediation_branch_name(repository_key: str, *, branch_suffix: str | None = None) -> str:
    suffix = _slug(branch_suffix or "") or secrets.token_hex(4)
    repo_slug = _slug(repository_key)[:64]
    return f"vanta/remediate-{repo_slug}-{suffix}"


def branch_suffix_from_request_id(request_id: str) -> str:
    return _slug(request_id)[-16:]


def _mask_secrets(value: str) -> str:
    masked = value
    for secret in (os.getenv("GITHUB_TOKEN"), os.getenv("GH_TOKEN"), os.getenv("OPENAI_API_KEY")):
        if secret:
            masked = masked.replace(secret, "***")
    return masked


def _log(logger, message: str, *, level: str = "info", **kwargs) -> None:
    if logger is None:
        return
    getattr(logger, level)(message, **kwargs)


def _openai_api_key() -> str:
    return (os.getenv("OPENAI_API_KEY") or os.getenv("CODEX_API_KEY") or "").strip()


def _display_command(command: list[str]) -> str:
    if len(command) >= 3 and command[:2] == ["sh", "-c"]:
        return "sh -c <agent-command>"
    return _mask_secrets(" ".join(command))


def _tail_lines(value: str, *, max_chars: int) -> list[str]:
    if not value:
        return []
    single_line = _single_line(value, max_chars=max_chars)
    return single_line.split("\\n")


def _single_line(value: str, *, max_chars: int) -> str:
    cleaned = _mask_secrets(value).replace("\r", "\\r").replace("\n", "\\n")
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[-max_chars:]
