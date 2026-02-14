from __future__ import annotations

from argparse import Namespace

from datafog_mcp.config import ServerConfig, ProxyConfig


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
    )
    config = ProxyConfig.from_args(args)

    assert config.target_command == "python"
    assert config.target_args == ["server.py"]
    assert config.engine == "smart"
    assert config.strategy == "token"
    assert config.entity_types == ["EMAIL", "SSN"]
