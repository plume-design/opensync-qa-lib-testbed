import tempfile
import marshal
import pytest


@pytest.fixture(scope="function")
def custom_temp_dir(tmp_path, monkeypatch):
    """Patch python's tempdir to use pytest's temporary directory."""
    monkeypatch.setattr(tempfile, "gettempdir", lambda: tmp_path)


def test_completions_dir_creted(custom_temp_dir, tmp_path):
    from osrt_cli_tools.tb_config_parser import ensure_cache_dir

    ensure_cache_dir()
    assert (tmp_path / "completions").exists()


def test_load_results_with_dump(custom_temp_dir, tmp_path, mock_opensync_testbed):
    from osrt_cli_tools.tb_config_parser import load_config

    location_config = load_config()
    cache_file = tmp_path / "completions" / "example-None.marshal"
    assert cache_file.exists()
    with open(cache_file, "rb") as marshalled:
        cached_config = marshal.load(marshalled)

    assert cached_config == location_config


def test_local_locations_with_dump(custom_temp_dir, tmp_path):
    from osrt_cli_tools.tb_config_parser import load_locations

    locations_path = tmp_path / "completions" / "config_locations.marshal"

    assert locations_path.exists() is False

    load_locations()

    assert locations_path.exists()
