from vanta_omens.models import RepositoryWorkItem


def test_repository_work_item_round_trips_with_aliases() -> None:
    item = RepositoryWorkItem.model_validate(
        {
            "repository_key": "github.com/acme/service",
            "clone_url": "https://github.com/acme/service.git",
            "asset": {
                "id": "asset-1",
                "name": "service",
                "assetType": "CODE_REPOSITORY",
                "scanners": [],
            },
            "vulnerabilities": [
                {
                    "id": "vuln-1",
                    "name": "CVE-1",
                    "targetId": "asset-1",
                }
            ],
        }
    )

    round_tripped = RepositoryWorkItem.model_validate(item.model_dump(by_alias=True))

    assert round_tripped.asset.asset_type == "CODE_REPOSITORY"
    assert round_tripped.vulnerabilities[0].target_id == "asset-1"


def test_repository_work_item_accepts_python_field_names() -> None:
    item = RepositoryWorkItem.model_validate(
        {
            "repository_key": "github.com/acme/service",
            "clone_url": "https://github.com/acme/service.git",
            "asset": {
                "id": "asset-1",
                "name": "service",
                "asset_type": "CODE_REPOSITORY",
                "scanners": [],
            },
            "vulnerabilities": [
                {
                    "id": "vuln-1",
                    "name": "CVE-1",
                    "target_id": "asset-1",
                }
            ],
        }
    )

    assert item.asset.asset_type == "CODE_REPOSITORY"
    assert item.vulnerabilities[0].target_id == "asset-1"
