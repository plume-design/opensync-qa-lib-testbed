NEW_SWITCH_CONFIGS_DIR = "/srv/tftp/switch-configs"
OLD_SWITCH_CONFIGS_DIR = "/home/plume/config-files"


def get_switch_config_path(server, manufacturer: str, model: str, switch_name: str) -> str:
    """
    Return path to switch config on testbed server.

    Returns empty string if switch config for specified manufacturer, model and switch name combination isn't present.
    """
    ext = "rsc" if manufacturer == "mikrotik" else "cfg"
    config_file_name = f"{manufacturer}_{model}_{switch_name}.{ext}"
    for configs_dir in NEW_SWITCH_CONFIGS_DIR, OLD_SWITCH_CONFIGS_DIR:
        switch_config_path = f"{configs_dir}/{config_file_name}"
        if server.run_raw(f"test -r {switch_config_path}")[0] == 0:
            return switch_config_path
    return ""
