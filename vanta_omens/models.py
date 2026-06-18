from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Vulnerability(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str | None = None
    integration_id: str | None = Field(default=None, alias="integrationId")
    package_identifier: str | None = Field(default=None, alias="packageIdentifier")
    vulnerability_type: str | None = Field(default=None, alias="vulnerabilityType")
    target_id: str | None = Field(default=None, alias="targetId")
    severity: str | None = None
    is_fixable: bool | None = Field(default=None, alias="isFixable")
    fixed_version: str | None = Field(default=None, alias="fixedVersion")
    remediate_by_date: str | None = Field(default=None, alias="remediateByDate")
    related_vulns: list[str] = Field(default_factory=list, alias="relatedVulns")
    related_urls: list[str] = Field(default_factory=list, alias="relatedUrls")
    external_url: str | None = Field(default=None, alias="externalURL")
    scan_source: str | None = Field(default=None, alias="scanSource")


class VulnerableAsset(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    asset_type: str = Field(alias="assetType")
    scanners: list[dict] = Field(default_factory=list)


class RepositoryWorkItem(BaseModel):
    repository_key: str
    clone_url: str
    asset: VulnerableAsset
    vulnerabilities: list[Vulnerability]


class RemediationResult(BaseModel):
    repository_key: str
    clone_url: str
    status: str
    branch: str | None = None
    pull_request_url: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    error: str | None = None
