from __future__ import annotations

from argparse import Namespace

from datafog_mcp.config import ProxyConfig, ServerConfig


def test_server_config_uses_cli_then_env_then_file_values(tmp_path, monkeypatch: object) -> None:
    config_file = tmp_path / "datafog-mcp.toml"
    config_file.write_text(
        """
[server]
engine = "regex"
strategy = "mask"
entity_types = ["SSN"]
verbose = true
transport = "stdio"
port = 8010
"""
    )

    monkeypatch.setenv("DATAFOG_ENGINE", "smart")
    monkeypatch.setenv("DATAFOG_STRATEGY", "hash")

    args = Namespace(
        engine="gliner",
        strategy=None,
        entities=None,
        verbose=None,
        transport=None,
        port=None,
        config=str(config_file),
    )

    config = ServerConfig.from_args(args)

    assert config.engine == "gliner"
    assert config.strategy == "hash"
    assert config.entity_types == ["SSN"]
    assert config.verbose is True
    assert config.transport == "stdio"
    assert config.port == 8010


def test_proxy_config_uses_env_when_not_set() -> None:
    args = Namespace(
        wrap=("python", "server.py"),
        engine=None,
        strategy=None,
        entities="EMAIL,SSN",
        verbose=None,
        config=None,
        intercept_tool_arguments=None,
        intercept_tool_responses=None,
        intercept_resources=None,
    )
    config = ProxyConfig.from_args(args)

    assert config.target_command == "python"
    assert config.target_args == ["server.py"]
    assert config.engine == "smart"
    assert config.strategy == "token"
    assert config.entity_types == ["EMAIL", "SSN"]


def test_server_config_uses_no_telemetry_flag(monkeypatch: object) -> None:
    args = Namespace(
        engine=None,
        strategy=None,
        entities=None,
        verbose=None,
        transport=None,
        port=None,
        config=None,
        no_telemetry=True,
    )
    config = ServerConfig.from_args(args)
    assert config.no_telemetry is True


def test_server_config_no_telemetry_respects_env(monkeypatch: object) -> None:
    monkeypatch.setenv("DATAFOG_NO_TELEMETRY", "true")

    args = Namespace(
        engine=None,
        strategy=None,
        entities=None,
        verbose=None,
        transport=None,
        port=None,
        config=None,
        no_telemetry=None,
    )
    config = ServerConfig.from_args(args)
    assert config.no_telemetry is True


def test_proxy_config_no_telemetry_respects_env(monkeypatch: object) -> None:
    monkeypatch.setenv("DATAFOG_NO_TELEMETRY", "1")

    args = Namespace(
        wrap=("python", "server.py"),
        engine=None,
        strategy=None,
        entities=None,
        verbose=None,
        config=None,
        intercept_tool_arguments=None,
        intercept_tool_responses=None,
        intercept_resources=None,
        no_telemetry=None,
    )
    config = ProxyConfig.from_args(args)
    assert config.no_telemetry is True


def test_proxy_config_merges_advanced_flags_from_env_and_cli(monkeypatch: object) -> None:
    monkeypatch.setenv("DATAFOG_INTERCEPT_TOOL_RESPONSES", "false")
    monkeypatch.setenv("DATAFOG_INTERCEPT_RESOURCES", "false")

    args = Namespace(
        wrap=("python", "server.py"),
        engine=None,
        strategy=None,
        entities=None,
        verbose=None,
        config=None,
        intercept_tool_arguments=True,
        intercept_tool_responses=None,
        intercept_resources=None,
    )
    config = ProxyConfig.from_args(args)

    assert config.intercept_tool_arguments is True
    assert config.intercept_tool_responses is False
    assert config.intercept_resources is False
