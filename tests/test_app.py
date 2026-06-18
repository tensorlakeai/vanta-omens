from vanta_omens.app import _pull_request_summary


def test_pull_request_summary_collects_urls_and_counts_statuses() -> None:
    summary = _pull_request_summary(
        [
            {
                "repository_key": "github.com/acme/service-a",
                "pull_request_url": "https://github.com/acme/service-a/pull/1",
                "status": "pull_request_created",
            },
            {
                "repository_key": "github.com/acme/service-b",
                "pull_request_url": None,
                "status": "no_changes",
            },
            {
                "repository_key": "github.com/acme/service-c",
                "pull_request_url": None,
                "status": "dry_run_changes",
            },
            {
                "repository_key": "github.com/acme/service-d",
                "pull_request_url": None,
                "status": "failed",
            },
        ]
    )

    assert summary == {
        "pull_request_count": 1,
        "pull_requests": [
            {
                "repository_key": "github.com/acme/service-a",
                "pull_request_url": "https://github.com/acme/service-a/pull/1",
            }
        ],
        "pull_request_created_count": 1,
        "no_changes_count": 1,
        "dry_run_changes_count": 1,
        "failed_count": 1,
    }
