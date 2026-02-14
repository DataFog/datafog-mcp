from datafog_mcp import __version__


def test_package_version() -> None:
    assert isinstance(__version__, str)
    assert __version__.count(".") >= 1
