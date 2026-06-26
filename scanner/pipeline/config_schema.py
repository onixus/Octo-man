from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


class RuntimeConfig(BaseModel):
    mode: Literal["safe", "balanced", "fast"] = "balanced"
    output_dir: str = "scanner/output"
    state_dir: str = "scanner/state"
    logs_dir: str = ""
    retries: int = Field(default=2, ge=0, le=10)
    timeout_seconds: int = Field(default=1800, ge=30, le=86400)
    nse_timeout_seconds: int = Field(default=600, ge=30, le=600)
    nse_concurrency: int = Field(default=4, ge=1, le=64)
    nse_max_rate: int = Field(default=0, ge=0)
    discover_concurrency: int = Field(default=1, ge=1, le=32)
    ports_concurrency: int = Field(default=1, ge=1, le=32)
    keep_intermediate: bool = True
    per_run_output: bool = True
    log_max_bytes: int = Field(default=10_485_760, ge=1024)  # 10 MiB
    log_backup_count: int = Field(default=5, ge=1, le=100)

    @model_validator(mode="after")
    def default_logs_dir(self) -> RuntimeConfig:
        if not self.logs_dir:
            self.logs_dir = f"{self.output_dir}/logs"
        return self


class ProfileConfig(BaseModel):
    discover_rate: int = Field(ge=1, le=100_000)
    port_rate: int = Field(ge=1, le=100_000)
    top_ports: int = Field(ge=1, le=65535)
    nmap_timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = "T4"
    nse_profile: str
    nse_concurrency: int | None = Field(default=None, ge=1, le=64)
    nse_max_rate: int | None = Field(default=None, ge=0)


class BatchingConfig(BaseModel):
    enabled: bool = True
    ipv4_prefix: int = Field(default=20, ge=8, le=30)
    max_targets_per_batch: int = Field(default=4096, ge=1, le=1_000_000)


class DiscoveryConfig(BaseModel):
    source: Literal["naabu"] = "naabu"
    skip_discovery: bool = False


class PortsConfig(BaseModel):
    source: Literal["naabu"] = "naabu"
    custom_ports_file: str = "scanner/inputs/ports.txt"


class NseProfileConfig(BaseModel):
    scripts: str = Field(min_length=1)
    version_detection: bool = True
    os_detection: bool = False


class ReportingConfig(BaseModel):
    markdown_summary: bool = True
    html_summary: bool = True
    csv_export: bool = True
    json_export: bool = True


class AppConfig(BaseModel):
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    profiles: dict[str, ProfileConfig]
    batching: BatchingConfig = Field(default_factory=BatchingConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    ports: PortsConfig = Field(default_factory=PortsConfig)
    nse_profiles: dict[str, NseProfileConfig]
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    @field_validator("profiles")
    @classmethod
    def require_standard_profiles(cls, profiles: dict[str, ProfileConfig]) -> dict[str, ProfileConfig]:
        for name in ("safe", "balanced", "fast"):
            if name not in profiles:
                raise ValueError(f"missing required profile '{name}'")
        return profiles

    @model_validator(mode="after")
    def profile_nse_refs_exist(self) -> AppConfig:
        for name, profile in self.profiles.items():
            if profile.nse_profile not in self.nse_profiles:
                raise ValueError(
                    f"profile '{name}' references unknown nse_profile '{profile.nse_profile}'"
                )
        if self.runtime.mode not in self.profiles:
            raise ValueError(f"runtime.mode '{self.runtime.mode}' is not defined in profiles")
        return self


def load_config(raw: dict[str, Any]) -> AppConfig:
    """Parse and validate a raw YAML dict. Raises pydantic.ValidationError on failure."""
    return AppConfig.model_validate(raw)


def format_validation_error(exc: ValidationError) -> str:
    lines = ["configuration validation failed:"]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"])
        lines.append(f"  - {loc}: {err['msg']}")
    return "\n".join(lines)
