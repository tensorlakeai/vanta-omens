from __future__ import annotations

import re
from collections import defaultdict

from vanta_omens.models import RepositoryWorkItem, Vulnerability, VulnerableAsset


REPO_URL_RE = re.compile(
    r"(?:https://|git@)(?:github\.com|gitlab\.com|bitbucket\.org)[:/][A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?"
)


def group_by_repository(
    vulnerabilities: list[Vulnerability],
    assets_by_target_id: dict[str, VulnerableAsset],
    repository_urls: dict[str, str],
) -> list[RepositoryWorkItem]:
    grouped: dict[str, list[Vulnerability]] = defaultdict(list)
    assets: dict[str, VulnerableAsset] = {}
    urls: dict[str, str] = {}

    for vuln in vulnerabilities:
        if not vuln.target_id:
            continue
        asset = assets_by_target_id.get(vuln.target_id)
        if not asset or asset.asset_type != "CODE_REPOSITORY":
            continue
        clone_url = resolve_clone_url(asset, vuln, repository_urls)
        if not clone_url:
            continue
        key = normalize_repository_key(clone_url)
        grouped[key].append(vuln)
        assets[key] = asset
        urls[key] = clone_url

    return [
        RepositoryWorkItem(
            repository_key=key,
            clone_url=urls[key],
            asset=assets[key],
            vulnerabilities=sorted(items, key=lambda vuln: vuln.id),
        )
        for key, items in sorted(grouped.items())
    ]


def resolve_clone_url(
    asset: VulnerableAsset,
    vulnerability: Vulnerability,
    repository_urls: dict[str, str],
) -> str | None:
    for key in (asset.id, asset.name, vulnerability.target_id):
        if key and key in repository_urls:
            return repository_urls[key]

    candidates = [asset.name, vulnerability.external_url or "", *vulnerability.related_urls]
    for scanner in asset.scanners:
        candidates.extend(str(value) for value in scanner.values() if isinstance(value, str))
        for tag in scanner.get("assetTags", []) or []:
            if isinstance(tag, dict):
                candidates.extend(str(value) for value in tag.values() if isinstance(value, str))

    for candidate in candidates:
        match = REPO_URL_RE.search(candidate)
        if match:
            return _https_clone_url(match.group(0))
    return None


def normalize_repository_key(clone_url: str) -> str:
    normalized = _https_clone_url(clone_url).removesuffix(".git")
    return normalized.removeprefix("https://")


def _https_clone_url(url: str) -> str:
    if url.startswith("git@"):
        host, path = url[4:].split(":", 1)
        return f"https://{host}/{path}"
    return url
