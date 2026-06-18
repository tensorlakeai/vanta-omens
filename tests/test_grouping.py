from vanta_omens.grouping import group_by_repository, normalize_repository_key, resolve_clone_url
from vanta_omens.models import Vulnerability, VulnerableAsset


def test_group_by_repository_uses_explicit_mapping() -> None:
    vuln = Vulnerability.model_validate(
        {
            "id": "vuln-1",
            "name": "CVE-1",
            "targetId": "asset-1",
            "severity": "HIGH",
        }
    )
    asset = VulnerableAsset.model_validate(
        {
            "id": "asset-1",
            "name": "backend-api",
            "assetType": "CODE_REPOSITORY",
            "scanners": [],
        }
    )

    grouped = group_by_repository(
        [vuln],
        {"asset-1": asset},
        {"backend-api": "https://github.com/acme/backend-api.git"},
    )

    assert len(grouped) == 1
    assert grouped[0].repository_key == "github.com/acme/backend-api"
    assert grouped[0].vulnerabilities == [vuln]


def test_resolve_clone_url_from_scanner_tags() -> None:
    vuln = Vulnerability.model_validate({"id": "vuln-1", "name": "CVE-1", "targetId": "asset-1"})
    asset = VulnerableAsset.model_validate(
        {
            "id": "asset-1",
            "name": "repo",
            "assetType": "CODE_REPOSITORY",
            "scanners": [
                {
                    "assetTags": [
                        {"key": "repository", "value": "https://github.com/acme/service.git"}
                    ]
                }
            ],
        }
    )

    assert resolve_clone_url(asset, vuln, {}) == "https://github.com/acme/service.git"


def test_normalize_git_ssh_repository_key() -> None:
    assert normalize_repository_key("git@github.com:acme/service.git") == "github.com/acme/service"
