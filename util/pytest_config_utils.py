def get_option_config_names(config):
    config_name = config.option.config_name
    if not config_name:
        configs = []
    else:
        configs = config_name.split(",")
    return configs


def is_parallel(config):
    if config.option.numprocesses or hasattr(config, "workerinput"):
        return True
    return False


def is_main_xdist(config):
    """True if the code running the given pytest.config object is running in a xdist master"""
    if not is_parallel(config):
        return False
    return not is_worker_xdist(config)


def is_worker_xdist(config):
    """True if the code running the given pytest.config object is running in a xdist worker"""
    if not is_parallel(config):
        return False
    return True if hasattr(config, "workerinput") else False


def get_option_config_name(config):
    config_names = get_option_config_names(config)
    number_of_configs = len(config_names)
    if number_of_configs == 0:
        config_name = None
    elif number_of_configs == 1:
        config_name = config_names[0]
    else:
        if not is_parallel(config):
            # User set multi configs but with numprocesses = 0
            config_name = config_names[0]
        elif is_worker_xdist(config):
            worker_idx = int(config.workerinput["workerid"].replace("gw", ""))
            config_name = config_names[worker_idx % number_of_configs]
        else:  # main xdist
            config_name = ""
    return config_name


def get_worker_for_tb_name(config, tb_name):
    config_names = get_option_config_names(config)
    idx = config_names.index(tb_name)
    return f"gw{idx}"


def get_param_value(item, key) -> str | None:
    """Returns the value of a parameter with a given name

    Args:
        item (_pytest.nodes.Item): pytest Item
        key (str): name of the parameter

    Returns:
        str | None: the value of a given parameter or None if it's not found
    """
    if not (callspec := getattr(item, "callspec", None)):
        return None
    if not (params := getattr(callspec, "params", None)):
        return None
    if key not in params:
        return None
    return params[key].replace(f"{key}_", "")
