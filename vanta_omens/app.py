from tensorlake.applications import (
    Image,
    Retries,
    application,
    function,
    run_local_application,
)

app_image = (
    Image(base_image="tensorlake/ubuntu-minimal")
    .run("apt-get update && apt-get install -y git curl ca-certificates")
    .run("pip install httpx pydantic tensorlake")
    .run(
        'npm install --global --ignore-scripts pnpm@11.28.5 && '
        'mkdir -p /usr/local/lib/tensorlake-tools && '
        'pnpm --dir /usr/local/lib/tensorlake-tools --config.minimumReleaseAge=1440 '
        '--config.minimumReleaseAgeStrict=true '
        '--config.minimumReleaseAgeIgnoreMissingTime=false '
        '--config.trustLockfile=false --config.blockExoticSubdeps=true '
        '--config.strictDepBuilds=true --config.optimisticRepeatInstall=false add '
        '--ignore-scripts --save-exact @openai/codex@0.161.0 && '
        'for executable in /usr/local/lib/tensorlake-tools/node_modules/.bin/*; do [ ! '
        '-e "$executable" ] || ln -sf "$executable" /usr/local/bin/; done'
    )
)

VANTA_SECRETS = ["VANTA_CLIENT_ID", "VANTA_CLIENT_SECRET"]
REMEDIATION_SECRETS = ["OPENAI_API_KEY", "GITHUB_TOKEN"]


@application()
@function(
    image=app_image,
    secrets=VANTA_SECRETS,
)
async def monitor_vanta_vulnerabilities() -> list[dict]:
    import asyncio

    from tensorlake.applications import Logger, RequestContext

    from vanta_omens.config import VantaSettings
    from vanta_omens.grouping import group_by_repository
    from vanta_omens.vanta import VantaClient, gather_code_repository_assets

    logger = Logger.get_logger(module="vanta_omens")
    try:
        request_id = RequestContext.get().request_id
    except Exception:
        request_id = ""
    branch_suffix = _branch_suffix(request_id)
    logger.info("Vanta vulnerability monitor started", status="started")
    settings = VantaSettings.from_env()
    logger.info(
        "Loaded monitor settings",
        status="settings_loaded",
        vanta_base_url=settings.vanta_base_url,
        vanta_page_size=settings.vanta_page_size,
        asset_fetch_concurrency=settings.vanta_asset_fetch_concurrency,
        repository_mapping_count=len(settings.repository_urls),
    )
    async with VantaClient(
        base_url=settings.vanta_base_url,
        client_id=settings.vanta_client_id,
        client_secret=settings.vanta_client_secret,
        scope=settings.vanta_scope,
        page_size=settings.vanta_page_size,
    ) as client:
        logger.info("Fetching open fixable Vanta vulnerabilities", status="fetching_vulnerabilities")
        vulnerabilities = await client.list_open_fixable_vulnerabilities()
        target_count = len({vuln.target_id for vuln in vulnerabilities if vuln.target_id})
        logger.info(
            "Fetched Vanta vulnerabilities",
            status="vulnerabilities_fetched",
            vulnerability_count=len(vulnerabilities),
            unique_target_count=target_count,
        )
        logger.info(
            "Resolving vulnerable assets",
            status="resolving_assets",
            unique_target_count=target_count,
            asset_fetch_concurrency=settings.vanta_asset_fetch_concurrency,
        )
        assets_by_target_id = await gather_code_repository_assets(
            client,
            vulnerabilities,
            concurrency=settings.vanta_asset_fetch_concurrency,
        )
        logger.info(
            "Resolved source repository assets",
            status="assets_resolved",
            code_repository_asset_count=len(assets_by_target_id),
        )
    work_items = group_by_repository(
        vulnerabilities, assets_by_target_id, settings.repository_urls
    )
    logger.info(
        "Grouped vulnerabilities by repository",
        status="repositories_grouped",
        repository_count=len(work_items),
        grouped_vulnerability_count=sum(len(item.vulnerabilities) for item in work_items),
    )
    if not work_items:
        logger.info("No source repositories require remediation", status="completed")
        return []

    logger.info(
        "Dispatching repository remediation functions",
        status="dispatching",
        repository_count=len(work_items),
        branch_suffix=branch_suffix,
    )
    results = await asyncio.gather(
        *(
            fix_repository_vulnerabilities(
                _remediation_payload(work_item, branch_suffix)
            )
            for work_item in work_items
        )
    )
    logger.info(
        "Vanta vulnerability monitor completed",
        status="completed",
        repository_count=len(results),
        success_count=sum(1 for result in results if result["status"] != "failed"),
        failure_count=sum(1 for result in results if result["status"] == "failed"),
    )
    pull_request_summary = _pull_request_summary(results)
    logger.info(
        "Repository remediation pull request summary",
        status="pull_request_summary",
        **pull_request_summary,
    )
    return results


@function(
    image=app_image,
    timeout=7200,
    memory=4,
    ephemeral_disk=20,
    retries=Retries(max_retries=1),
    secrets=REMEDIATION_SECRETS,
)
async def fix_repository_vulnerabilities(payload: dict) -> dict:
    import os

    from tensorlake.applications import Logger

    from vanta_omens.config import AgentSettings
    from vanta_omens.models import RepositoryWorkItem
    from vanta_omens.remediate import remediate_repository

    logger = Logger.get_logger(module="vanta_omens")
    work_item = RepositoryWorkItem.model_validate(payload["work_item"])
    branch_suffix = str(payload["branch_suffix"])
    repo_logger = logger.bind(
        repository_key=work_item.repository_key,
        clone_url=work_item.clone_url,
        vulnerability_count=len(work_item.vulnerabilities),
        branch_suffix=branch_suffix,
    )
    repo_logger.info("Repository remediation started", status="started")
    settings = AgentSettings.from_env()
    repo_logger.info(
        "Repository remediation settings loaded",
        status="settings_loaded",
        model=settings.code_agent_model,
        dry_run=settings.dry_run,
        has_openai_api_key=bool(os.getenv("OPENAI_API_KEY")),
        has_codex_api_key=bool(os.getenv("CODEX_API_KEY")),
    )
    result = remediate_repository(
        work_item,
        model=settings.code_agent_model,
        command_template=settings.code_agent_command,
        dry_run=settings.dry_run,
        branch_suffix=branch_suffix,
        logger=repo_logger,
    )
    if result.status == "failed":
        repo_logger.error(
            "Repository remediation failed",
            status=result.status,
            branch=result.branch,
            error=result.error,
        )
    else:
        repo_logger.info(
            "Repository remediation finished",
            status=result.status,
            branch=result.branch,
            pull_request_url=result.pull_request_url,
            changed_file_count=len(result.changed_files),
        )
    return result.model_dump()


def _branch_suffix(request_id: str) -> str:
    import secrets

    from vanta_omens.remediate import branch_suffix_from_request_id

    return branch_suffix_from_request_id(request_id) if request_id else secrets.token_hex(4)


def _remediation_payload(work_item, branch_suffix: str) -> dict:
    return {
        "work_item": work_item.model_dump(by_alias=True),
        "branch_suffix": branch_suffix,
    }


def _pull_request_summary(results: list[dict]) -> dict:
    pull_requests = [
        {
            "repository_key": result["repository_key"],
            "pull_request_url": result["pull_request_url"],
        }
        for result in results
        if result.get("pull_request_url")
    ]
    return {
        "pull_request_count": len(pull_requests),
        "pull_requests": pull_requests,
        "pull_request_created_count": sum(1 for result in results if result["status"] == "pull_request_created"),
        "no_changes_count": sum(1 for result in results if result["status"] == "no_changes"),
        "dry_run_changes_count": sum(1 for result in results if result["status"] == "dry_run_changes"),
        "failed_count": sum(1 for result in results if result["status"] == "failed"),
    }


if __name__ == "__main__":
    request = run_local_application(monitor_vanta_vulnerabilities)
    print(request.output())
