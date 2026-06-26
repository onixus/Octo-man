from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.pipeline.config_schema import AppConfig, format_validation_error, load_config


def _minimal_config(**overrides: object) -> dict:
    base = {
        "runtime": {"mode": "balanced"},
        "profiles": {
            "safe": {
                "discover_rate": 1000,
                "port_rate": 1000,
                "top_ports": 100,
                "nmap_timing": "T3",
                "nse_profile": "baseline",
            },
            "balanced": {
                "discover_rate": 3000,
                "port_rate": 3000,
                "top_ports": 1000,
                "nmap_timing": "T4",
                "nse_profile": "baseline",
            },
            "fast": {
                "discover_rate": 7000,
                "port_rate": 7000,
                "top_ports": 1000,
                "nmap_timing": "T4",
                "nse_profile": "baseline",
            },
        },
        "nse_profiles": {
            "baseline": {"scripts": "default,safe"},
        },
    }
    base.update(overrides)
    return base


def test_load_config_accepts_minimal_valid():
    cfg = load_config(_minimal_config())
    assert cfg.runtime.mode == "balanced"
    assert cfg.profiles["safe"].top_ports == 100


def test_load_config_rejects_unknown_runtime_mode():
    raw = _minimal_config()
    raw["runtime"] = {"mode": "turbo"}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_load_config_rejects_missing_nse_profile_ref():
    raw = _minimal_config()
    raw["profiles"]["balanced"]["nse_profile"] = "missing"
    with pytest.raises(ValidationError) as exc:
        load_config(raw)
    msg = format_validation_error(exc.value)
    assert "nse_profile" in msg


def test_load_config_rejects_invalid_ipv4_prefix():
    raw = _minimal_config()
    raw["batching"] = {"ipv4_prefix": 99}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_load_config_rejects_nse_timeout_above_ten_minutes():
    raw = _minimal_config()
    raw["runtime"] = {"nse_timeout_seconds": 601}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_default_yaml_parses():
    import yaml

    text = Path("scanner/config/default.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.runtime.per_run_output is True
    assert cfg.runtime.nse_timeout_seconds == 600
