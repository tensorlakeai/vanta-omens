# Vanta Omens

Tensorlake Orchestrate application that runs daily, reads open Vanta vulnerabilities, filters them to source-control repository assets, groups them by repository, and dispatches one sandboxed remediation function per repository.

Repository remediation is fanned out with Tensorlake async functions so each repository runs concurrently in its own sandbox.

## Prerequisites

- `uv`
- Tensorlake CLI access through the project environment
- Tensorlake, Vanta, OpenAI, and GitHub credentials

## Configuration

Minimum required runtime secrets:

| Name | Used by | Purpose | Where to get it |
| --- | --- | --- | --- |
| `VANTA_CLIENT_ID` | Monitor function | Manage Vanta OAuth client ID | Create a Manage Vanta application in the [Vanta Developer Console](https://app.vanta.com/developer) |
| `VANTA_CLIENT_SECRET` | Monitor function | Manage Vanta OAuth client secret | Generated with the same Manage Vanta application |
| `GITHUB_TOKEN` | Remediation function | Authenticated clones, branch pushes, and pull request creation | Create a GitHub fine-grained personal access token from [GitHub Developer settings](https://github.com/settings/personal-access-tokens/new) |
| `OPENAI_API_KEY` | Remediation function | API key used by the Codex remediation agent | Create an API key from the [OpenAI API keys page](https://platform.openai.com/api-keys) |

The Vanta application should use the [Manage Vanta API](https://developer.vanta.com/reference/manage-vanta/overview) `client_credentials` flow with a read scope such as `vanta-api.all:read`. Vanta documents this flow as exchanging the application `client_id` and `client_secret` at `/oauth/token` for a bearer token.

For `GITHUB_TOKEN`, prefer a [fine-grained personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) limited to the repositories this app can remediate. It needs enough repository access to clone, push branches, and create pull requests. For GitHub repositories, that normally means `Contents: Read and write` and `Pull requests: Read and write`.

`OPENAI_API_KEY` is passed to the Codex CLI as both `OPENAI_API_KEY` and `CODEX_API_KEY` inside the remediation sandbox.

Common options:

| Name | Default | Purpose |
| --- | --- | --- |
| `VANTA_BASE_URL` | `https://api.vanta.com` | Use `https://api.vanta-gov.com` for GovCloud |
| `VANTA_SCOPE` | `vanta-api.all:read` | Manage Vanta OAuth scope |
| `VANTA_PAGE_SIZE` | `100` | Vanta page size |
| `VANTA_ASSET_FETCH_CONCURRENCY` | `10` | Maximum concurrent Vanta asset lookup requests |
| `REPOSITORY_URLS_JSON` | `{}` | JSON map from Vanta asset id/name/target id to clone URL |
| `CODE_AGENT_MODEL` | `gpt-4.1-mini` | Cheap, fast coding model for the agent command |
| `CODE_AGENT_COMMAND` | `codex exec --model {model} --sandbox workspace-write - < {prompt_file}` | Remediation command template |
| `DRY_RUN` | `false` | If true, clone and run the agent but do not push or open PRs |

`REPOSITORY_URLS_JSON` is useful because Vanta source-control assets do not always expose a clone URL. Example:

```json
{
  "backend-api": "https://github.com/acme/backend-api.git",
  "a2f7e1b9d0c3f4e5a6c7b8d9": "https://github.com/acme/frontend.git"
}
```

## Deploy

Run deployment from the repository root and deploy the root [app.py](app.py). Do not run `tl deploy app.py` from inside `vanta_omens/`; Tensorlake uses the deploy file's directory as the code root, and deploying from the package directory omits the `vanta_omens` package name at runtime.

```bash
cd /path/to/vanta-omens
uv sync
uv run tl secrets set VANTA_CLIENT_ID=... VANTA_CLIENT_SECRET=... OPENAI_API_KEY=... GITHUB_TOKEN=...
uv run tl deploy app.py
```

Create the daily Tensorlake cron schedule after deployment:

```bash
uv run tl cron create monitor_vanta_vulnerabilities --schedule "0 9 * * *" --input-json null
```

## Local Run

```bash
uv run python -m vanta_omens.app
```

## Test

```bash
uv run pytest
```

## Node tool installation policy

Owned image and workstation tool installs bootstrap only pnpm 11.28.5 with
npm hooks disabled, then install reviewed tool pins with a strict 24-hour
publication delay, required timestamps, and disabled lifecycle hooks. Global
installs receive the policy explicitly; a project workspace policy does not
cover global installation. Upgrade the pinned tools through review. Node.js
22 or newer is required. Image builds and workstation bootstrap are not run
by this migration; existing tool binary paths are preserved.
