from __future__ import annotations

import os
import copy
import json
import random
import re
from typing import TypedDict
from pathlib import Path
import yaml
import subprocess
from cryptography.fernet import Fernet
from lib_testbed.generic.util.common import DeviceCommon
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import BASE_DIR

CONFIG_DIR = "config"
LOCATIONS_DIR = "locations"
LOBS_DIR = "labs"
DEPLOYMENTS_DIR = "deployments"
SPHERES_DIR = "spheres"
MISCS_DIR = "miscs"
TOKEN_DIR = "/tmp/automation/tokens"
MODEL_PROPERTIES_DIR = "model_properties"
MODEL_INTERNAL_DIR = "internal"
MODEL_REFERENCE_DIR = "reference"
CLIENT_DIR = "tb_clients"
ENV_OPENSYNC_TESTBED = "OPENSYNC_TESTBED"
TBCFG_PROFILE = "profile"
TBCFG_NODES = "Nodes"
TBCFG_CLIENTS = "Clients"
TBCFG_SSH_GATEWAY = "ssh_gateway"
DEC_KEY_PREFIX = "autotest_clean_"
LOCAL_HOST_CLIENT_NAME = "host"
REMOTE_HOST_CLIENT_NAME = "remote_host"
IPTV_HOST_CLIENT_NAME = "iptv_host"
S2S_VPN_HOST_CLIENT_NAME = "s2s_vpn_host"
P2S_VPN_HOST_CLIENT_NAME = "p2s_vpn_host"
MOTION_HOST_CLIENT_NAME = "motion_host"
IPERF_CLIENT_TYPE = "iperf_host"
FIXED_HOST_CLIENTS = [
    LOCAL_HOST_CLIENT_NAME,
    REMOTE_HOST_CLIENT_NAME,
    IPTV_HOST_CLIENT_NAME,
    S2S_VPN_HOST_CLIENT_NAME,
    P2S_VPN_HOST_CLIENT_NAME,
    MOTION_HOST_CLIENT_NAME,
]
RANDOM_KEY = b"GZWKEhHGNopxRdOHS4H4IyKhLQ8lwnyU7vRLrM3sebY="


def load_file(file_name):
    extension = os.path.splitext(file_name)[1]
    with open(file_name, "r") as stream:
        if extension == ".yaml":
            base_config_name = "generic_global"
            ret_dict = yaml.load(stream, YamlLoader)
            tmp_dict = {}
            base_dict = ret_dict.get(base_config_name)
            if base_dict:
                while base_dict:
                    tmp_dict = dict_deep_update(copy.deepcopy(base_dict), tmp_dict)
                    base_dict = base_dict.get(base_config_name)
                ret_dict = dict_deep_update(tmp_dict, ret_dict)
                ret_dict.pop(base_config_name)
        elif extension == ".json":
            base_config_name = "base_config"
            ret_dict = json.loads(stream.read())
            if base_config_name in ret_dict:
                base_config = ret_dict[base_config_name]
                base_config_path = os.path.join(os.path.dirname(file_name), base_config)
                if not base_config_path.endswith(".json"):
                    base_config_path += ".json"
                new_ret_dict = load_file(base_config_path)
                new_ret_dict.update(ret_dict)
                ret_dict = new_ret_dict.copy()
        elif extension == ".txt":
            return stream.read()
        else:
            raise OpenSyncException(f"Invalid file extension: {file_name}", "Only use json/yaml files!")
        return ret_dict


def merge(source, destination):
    for key, value in source.items():
        if isinstance(value, dict):
            node = destination.setdefault(key, {})
            merge(value, node)
        else:
            destination[key] = value
    return destination


def find_file(dir_names, file_name, extension="yaml"):
    for dir_name in dir_names:
        list_dir = os.listdir(dir_name)
        if not file_name.endswith(extension):
            file_name += f".{extension}"
        for file in list_dir:
            if re.compile(file_name).match(file):
                file = dir_name + "/" + file
                return file
    raise OpenSyncException(
        f"Cannot find config file {file_name}", f"Expecting config file: {file_name} in {dir_names}"
    )


def get_config_dir():
    return os.path.join(BASE_DIR, CONFIG_DIR)


def get_config_dirs():
    dirs = [os.path.join(BASE_DIR, CONFIG_DIR)]
    if os.path.exists(os.path.join(BASE_DIR, "mobile")):
        dirs.append(os.path.join(BASE_DIR, "mobile", CONFIG_DIR))
    if os.path.exists(os.path.join(BASE_DIR, "web")):
        dirs.append(os.path.join(BASE_DIR, "web", CONFIG_DIR))
    return dirs


def get_model_properties_dirs(device_type="node"):
    if device_type == "node":
        return [
            os.path.join(BASE_DIR, CONFIG_DIR, MODEL_PROPERTIES_DIR, MODEL_INTERNAL_DIR),
            os.path.join(BASE_DIR, CONFIG_DIR, MODEL_PROPERTIES_DIR, MODEL_REFERENCE_DIR),
        ]
    else:
        return [
            os.path.join(BASE_DIR, CONFIG_DIR, MODEL_PROPERTIES_DIR, MODEL_INTERNAL_DIR, CLIENT_DIR),
            os.path.join(BASE_DIR, CONFIG_DIR, MODEL_PROPERTIES_DIR, MODEL_REFERENCE_DIR, CLIENT_DIR),
        ]


def find_location_file(name):
    location_dirs = []
    config_dirs = get_config_dirs()
    for config_dir in config_dirs:
        location_dirs.append(os.path.join(config_dir, LOCATIONS_DIR))
    return find_file(location_dirs, name)


def find_deployment_file(name):
    return find_file([os.path.join(get_config_dir(), DEPLOYMENTS_DIR)], name)


def find_sphere_file(name):
    return find_file([os.path.join(get_config_dir(), SPHERES_DIR)], name)


def find_default_deployment_file(config):
    if os.path.basename(config.get("location_file")).startswith("test-tb"):
        # For unit test use example deployment
        return find_file([os.path.join(get_config_dir(), DEPLOYMENTS_DIR)], "example")
    names = ["dogfood", "(?!example).*"]  # 'opensync',
    for name in names:
        try:
            dpl_file = find_file([os.path.join(get_config_dir(), DEPLOYMENTS_DIR)], name)
            if "dogfood" not in os.path.basename(dpl_file):
                log.info(f"Default config: {dpl_file}")
            break
        except OpenSyncException:
            continue
    else:
        raise OpenSyncException("Cannot find default config file", "Check if config file is not missing")
    return dpl_file


def find_lab_tb_list_file(name, **kwargs):
    labs_dir = os.path.join(BASE_DIR, CONFIG_DIR, LOBS_DIR)
    return find_file([labs_dir], name, **kwargs)


def find_config_file_regex(regex):
    config_files = os.listdir(os.path.join(BASE_DIR, CONFIG_DIR, LOCATIONS_DIR))
    return [f.split(".")[0] for f in config_files if re.match(f"{regex}\\.yaml", f)]


def get_deployment(config, default_deployment=None):
    """
    Get current deployment for a location
    Args:
        config: (dict) location config
        default_deployment: (str) default deployment for a location (in case cannot be discovered from inventory)

    Returns: (str) deployment name

    """
    deployment_name = config.get(TBCFG_PROFILE)
    if not deployment_name:
        raise OpenSyncException("Missing profile setting in config file")
    if deployment_name == "auto":
        try:
            from lib.cloud.api import inventory
        except ModuleNotFoundError:
            raise OpenSyncException(
                "Inventory API does not exist", "Change auto profile in location config to deployment name"
            )
        conf = load_file(find_default_deployment_file(config))
        inv = inventory.Inventory.fromurl(conf["inventory_url"], conf["inv_user"], conf["inv_pwd"])
        serial = config["Nodes"][0]["id"]
        deployment_name = inv.get_node(serial).get("deployment")
        if not deployment_name:
            if default_deployment:
                deployment_name = default_deployment
            else:
                raise OpenSyncException("Deployment name is set to auto and cannot be discovered from Inventory")
        if deployment_name == "dog1":
            deployment_name = "dogfood"
    return deployment_name


def get_misc_files():
    try:
        config_dir = Path(get_config_dir())
        miscs_dir = config_dir.joinpath(MISCS_DIR)
        if not miscs_dir.is_dir():
            miscs_dir = min(Path(BASE_DIR).glob(f"**/{MISCS_DIR}"))
        misc_files = [file.as_posix() for file in miscs_dir.iterdir()]
        return misc_files
    except FileNotFoundError:
        return []


def get_tokens_from_files():
    try:
        return [os.path.join(TOKEN_DIR, token_file) for token_file in os.listdir(TOKEN_DIR)]
    except FileNotFoundError:
        return []


def attach_capabilities_cfg_to_nodes(config):
    for node in config.get(TBCFG_NODES, []):
        # capabilities can be also overwritten in the location config
        capab = get_model_capabilities(node["model"])
        node["capabilities"] = dict_deep_update(capab, node.get("capabilities", {}))
        node["model_org"] = node["model"]
        node["model"] = DeviceCommon.convert_model_name(node["model_org"])
        update_device_host_cfg(device_config=node, capabilities_config=node["capabilities"])


def attach_capabilities_cfg_to_clients(config):
    for client in config.get(TBCFG_CLIENTS, []):
        # No longer supported.
        if client["type"] == "pod":
            continue
        # capabilities can be also overwritten in the location config
        client_cfg = get_model_capabilities(client["type"], device_type="client")
        update_device_host_cfg(device_config=client, capabilities_config=client_cfg)
        client["capabilities"] = client_cfg


def update_ssh_gateway_config(config):
    ssh_gateway_config = config.get(TBCFG_SSH_GATEWAY, {})
    # Use rpi_server model capabilities for ssh_gateway defaults.
    capabilities_config = get_model_capabilities("rpi_server", device_type="client")
    if "user" not in ssh_gateway_config:
        ssh_gateway_config["user"] = capabilities_config.get("username")
    if "pass" not in ssh_gateway_config:
        ssh_gateway_config["pass"] = capabilities_config.get("password")


def update_device_host_cfg(device_config, capabilities_config):
    user_name, password = capabilities_config.get("username"), capabilities_config.get("password")
    if device_config.get("host"):
        if "user" not in device_config["host"]:
            device_config["host"]["user"] = user_name
        if "pass" not in device_config["host"]:
            device_config["host"]["pass"] = password


def remove_ssh_key_files(config):
    def update_single_host(host_info):
        if not host_info.get("opts", {}).get("IdentityFile"):
            return
        if DEC_KEY_PREFIX not in host_info["opts"]["IdentityFile"]:
            return
        try:
            # use subprocess to hide system prints
            subprocess.run(["rm", host_info["opts"]["IdentityFile"]], capture_output=True)
        except OSError:
            pass

    if config.get("ssh_gateway"):
        update_single_host(config["ssh_gateway"])

    for group in [TBCFG_NODES, TBCFG_CLIENTS]:
        if not config.get(group):
            continue
        for device in config[group]:
            if device.get("host"):
                update_single_host(device["host"])
            # handle case with overwritten ssh_gateway for a device (rev_ssh case)
            if device.get("ssh_gateway"):
                update_single_host(device["ssh_gateway"])


def decrypt_ssh_key(config):
    def update_single_host(host_info):
        if not host_info.get("ssh_key_passphrase"):
            return
        if not host_info.get("opts", {}).get("IdentityFile"):
            raise Exception("Missing path to IdentityFile in config file, while using ssh key passphrase")
        if key_matching.get(host_info["opts"]["IdentityFile"]):
            host_info["opts"]["IdentityFile"] = key_matching[host_info["opts"]["IdentityFile"]]
            return
        if host_info["ssh_key_passphrase"] == "SSH_PASSPHRASE_FROM_VAULT":
            if ssh_key_passphrase := key_matching.get("ext_passphrase"):
                pass
            else:
                from lib.util.rdkautotoollib import get_pass_phrase

                ssh_key_passphrase = get_pass_phrase()
                key_matching["ext_passphrase"] = ssh_key_passphrase
        else:
            ssh_key_passphrase = host_info["ssh_key_passphrase"]

        new_file = f"/tmp/{DEC_KEY_PREFIX}{random.randint(10000, 99999)}"
        os.system(f"cp {host_info['opts']['IdentityFile']} {new_file}")
        # make sure file is writable
        os.system(f"chmod 600 {new_file}")
        # use subprocess to hide system prints
        ret = subprocess.run(
            ["ssh-keygen", "-p", "-P", ssh_key_passphrase, "-N", "", "-f", new_file], capture_output=True
        )
        if ret.returncode:
            log.error(f"Cannot decrypt the key: {ret.stderr}")
        key_matching[host_info["opts"]["IdentityFile"]] = new_file
        host_info["opts"]["IdentityFile"] = new_file

    key_matching = {}
    if config.get("ssh_gateway"):
        update_single_host(config["ssh_gateway"])

    for group in [TBCFG_NODES, TBCFG_CLIENTS]:
        if not config.get(group):
            continue
        for device in config[group]:
            if device.get("host"):
                update_single_host(device["host"])
            # handle case with overwritten ssh_gateway for a device (rev_ssh case)
            if device.get("ssh_gateway"):
                update_single_host(device["ssh_gateway"])


def load_tb_config(  # noqa: C901
    location_file=None,
    deployment_file=None,
    sphere_file=None,
    skip_deployment=False,  # noqa:C901
    skip_capabilities=False,
) -> TbConfig:
    """
    Load test bed configuration file
    Args:
        location_file: (str) test bed name
        deployment_file: (str) deployment name
        sphere_file: (str) sphere name
        skip_deployment: (bool) if only location config is needed
        skip_capabilities: (bool) if model capabilities are not needed

    Returns: (dict) loaded configuration

    """
    if location_file and not os.path.isabs(location_file):
        location_file = find_location_file(location_file)
    elif not location_file and not deployment_file and not sphere_file:
        location_file = os.environ.get(ENV_OPENSYNC_TESTBED)
        if not location_file:
            raise OpenSyncException(
                f"{ENV_OPENSYNC_TESTBED} environment variable not set", "Run pset tool to configure testbed"
            )
        location_file = find_location_file(location_file)

    if location_file:
        config = load_file(location_file)
        if "include_file" in config:
            location_file = config["include_file"]
        if "hydra" in config:
            config[TBCFG_CLIENTS].extend(config.pop("hydra"))
        if not skip_capabilities:
            attach_capabilities_cfg_to_nodes(config)
            attach_capabilities_cfg_to_clients(config)
        update_ssh_gateway_config(config)
        decrypt_ssh_key(config)
        networks = config.get("Networks")
        if isinstance(networks, list):
            for net_data in networks:
                if "key" in net_data:
                    net_data["key"] = str(net_data["key"])
    else:
        config = {}
    if "include_file" not in config:
        config["location_file"] = location_file
    else:
        config["location_file"] = config["include_file"]

    if not skip_deployment:
        if deployment_file and not os.path.isabs(deployment_file) and location_file:
            if config.get(TBCFG_PROFILE) != "auto" and config.get(TBCFG_PROFILE) != deployment_file:
                log.info(
                    f'Can not move location to "{deployment_file}" deployment because '
                    f"profile field in config is not set to auto. Using {config.get(TBCFG_PROFILE)}"
                )
                deployment_file = None
            elif config.get(TBCFG_PROFILE) == "auto":
                loc_deployment = get_deployment(config, default_deployment=deployment_file)
                if loc_deployment != deployment_file:
                    log.info("Testbed will be moved to %s once reservation is acquired", deployment_file)
                    deployment_file = None
                else:
                    deployment_file = find_deployment_file(deployment_file)
            else:
                deployment_file = None
        elif deployment_file and not os.path.isabs(deployment_file) and not location_file:
            deployment_file = find_deployment_file(deployment_file)

        if not deployment_file and config.get(TBCFG_PROFILE):
            deployment_name = get_deployment(config)
            deployment_file = find_deployment_file(deployment_name)

        if deployment_file:
            config["deployment_file"] = deployment_file
            config[TBCFG_PROFILE] = os.path.basename(deployment_file).split(".")[0]
            include = load_file(deployment_file)
            if include:
                config = merge(config, include)

    if sphere_file:
        sphere_file = find_sphere_file(sphere_file)
        include = load_file(sphere_file)
        if include:
            config = merge(config, include)

    update_config_with_admin_creds(config)

    misc_files = get_misc_files()
    for misc_file in misc_files:
        include = load_file(misc_file)
        if include:
            config = merge(config, include)

    token_files = get_tokens_from_files()
    for token_file in token_files:
        include = load_file(token_file)
        if include:
            config = merge(config, include)

    if not config.get("email") and "UPRISE" not in config.get("capabilities", []):
        config["email"] = config.get("default_email")
        config["password"] = config.get("default_password")
        if "user_name" not in config:
            config["user_name"] = config.get("default_user_name", "")

    update_uprise_config(config=config)
    init_fixed_host_clients(tb_config=config)

    return config


def update_uprise_config(config):
    if "UPRISE" not in config.get("capabilities", []):
        return
    for location_cfg in config["locations"]:
        # Update locations according to used nodes
        location_cfg["Nodes"] = get_uprise_location_nodes(base_config=config, uprise_loc_cfg=location_cfg)
        # Update locations according to used clients
        location_cfg["Clients"] = get_uprise_location_clients(base_config=config, uprise_loc_cfg=location_cfg)
        # Update locations according to default property
        location_cfg["PropertyConfig"] = get_uprise_location_property(base_config=config, uprise_loc_cfg=location_cfg)


def init_fixed_host_clients(tb_config):
    if not tb_config.get("Clients"):
        tb_config["Clients"] = []

    # Init local host, remote iperf server, iptv-host as a fixed clients
    ssh_gateway = tb_config.get("ssh_gateway", {})
    if not next(filter(lambda client_cfg: client_cfg["name"] == LOCAL_HOST_CLIENT_NAME, tb_config["Clients"]), None):
        tb_config["Clients"].append(_generate_host_config(ssh_gateway, LOCAL_HOST_CLIENT_NAME))

    if not next(filter(lambda client_cfg: client_cfg["name"] == IPTV_HOST_CLIENT_NAME, tb_config["Clients"]), None):
        tb_config["Clients"].append(_generate_host_config(ssh_gateway, IPTV_HOST_CLIENT_NAME, "nsiptv"))

    if not any(client for client in tb_config["Clients"] if client.get("name") == S2S_VPN_HOST_CLIENT_NAME):
        tb_config["Clients"].append(
            _generate_host_config(ssh_gateway, S2S_VPN_HOST_CLIENT_NAME, "s2s-host", interface_name="s2s-host-int")
        )

    if not any(client for client in tb_config["Clients"] if client.get("name") == P2S_VPN_HOST_CLIENT_NAME):
        tb_config["Clients"].append(
            _generate_host_config(ssh_gateway, P2S_VPN_HOST_CLIENT_NAME, "rw-host", interface_name="rw-host-int")
        )

    if not any(client for client in tb_config["Clients"] if client.get("name") == MOTION_HOST_CLIENT_NAME):
        turntable_host = tb_config.get(MOTION_HOST_CLIENT_NAME, ssh_gateway)
        tb_config["Clients"].append(_generate_remote_config(turntable_host, MOTION_HOST_CLIENT_NAME, "rpi"))

    if not next(filter(lambda client_cfg: client_cfg["name"] == REMOTE_HOST_CLIENT_NAME, tb_config["Clients"]), None):
        remote_host = tb_config.get("iperf3_check")
        if remote_host:
            tb_config["Clients"].append(_generate_remote_config(remote_host, REMOTE_HOST_CLIENT_NAME, "linux"))
    set_iperf_host(tb_config=tb_config)


def _generate_host_config(ssh_gateway_config, client_name, namespace_name=None, interface_name=None):
    client_cfg = get_model_capabilities(ssh_gateway_config.get("type", "rpi_server"), device_type="client")
    host_configuration = {
        "name": client_name,
        "type": ssh_gateway_config.get("type", "rpi"),
        "capabilities": client_cfg,
        IPERF_CLIENT_TYPE: False,
    }
    host_configuration.update(ssh_gateway_config)
    if namespace_name:
        host_configuration["netns"] = namespace_name
    if interface_name:
        host_configuration["iface"] = interface_name
    return host_configuration


def _generate_remote_config(remote_host_config, client_name, default_type):
    client_type = remote_host_config.get("type", default_type)
    host_configuration = {
        "name": client_name,
        "ssh_gateway": remote_host_config,
        "type": client_type,
        "hostname": remote_host_config.get("hostname"),
        IPERF_CLIENT_TYPE: False,
    }
    return host_configuration


def set_iperf_host(tb_config):
    if "CMTS" in tb_config.get("capabilities", []) or (
        "LTE" in tb_config.get("capabilities", []) and tb_config.get("runtime_lte_only_uplink")
    ):
        iperf_client_name = REMOTE_HOST_CLIENT_NAME
    else:
        iperf_client_name = LOCAL_HOST_CLIENT_NAME
    iperf_client_cfg = next(filter(lambda client_cfg: client_cfg["name"] == iperf_client_name, tb_config["Clients"]))
    iperf_client_cfg[IPERF_CLIENT_TYPE] = True


def get_uprise_location_nodes(base_config, uprise_loc_cfg):
    location_nodes = list()
    for node in base_config["Nodes"]:
        if node["default_location"] != uprise_loc_cfg["user_name"]:
            continue
        location_nodes.append(node)
    return location_nodes


def get_uprise_location_clients(base_config, uprise_loc_cfg):
    location_clients = list()
    for client in base_config["Clients"]:
        if client["default_location"] != uprise_loc_cfg["user_name"]:
            continue
        location_clients.append(client)
    return location_clients


def get_uprise_location_property(base_config, uprise_loc_cfg):
    default_uprise_property = dict()
    for uprise_property in base_config["properties"]:
        if uprise_property["property_name"] != uprise_loc_cfg["default_property"]:
            continue
        default_uprise_property = uprise_property
        break
    return default_uprise_property


def get_location_name(config):
    # USTB based uprise config
    if location_file := config.get("ssh_gateway", {}).get("location_file"):
        return os.path.basename(location_file).split(".")[0]
    elif location_file := config.get("location_file"):
        return os.path.basename(location_file).split(".")[0]
    else:
        return "unknown"


def get_deployment_name(config):
    if deployment_file := config.get("deployment_file"):
        return os.path.basename(deployment_file).split(".")[0]
    else:
        return "unknown"


def get_model_capabilities(model, device_type="node"):
    model = DeviceCommon.convert_model_name(model)
    # either model properties file is in internal or external directory
    for cap_dir in get_model_properties_dirs(device_type=device_type):
        cap_file = os.path.join(cap_dir, f"{model}.yaml")
        if os.path.exists(cap_file):
            break
    else:
        # Assuming new model configs will be added here
        raise Exception(f"Cannot find model properties file for {model}. Make sure {cap_file} exists")
    with open(cap_file) as cap:
        capab = yaml.load(cap, YamlLoader)
    if device_type == "client":
        return capab
    supported_bands = []
    for band, mode in capab["interfaces"]["radio_hw_mode"].items():
        if mode is None:
            continue
        band = "2.4G" if band == "24g" else band.upper()
        supported_bands.append(band)
    capab["supported_bands"] = supported_bands
    # in case of regex signs in bhaul names copy key as re_*
    backhaul_ap_24g = list(capab["interfaces"]["backhaul_ap"].values())[0]
    if backhaul_ap_24g is not None and any([char in backhaul_ap_24g for char in ["(", ")", "?", "*"]]):
        capab["interfaces"]["re_backhaul_ap"] = capab["interfaces"]["backhaul_ap"].copy()
        for band, mode in capab["interfaces"]["backhaul_ap"].items():
            if mode is None:
                continue
            capab["interfaces"]["backhaul_ap"][band] = re.sub(r"\(|\)|\?|\*", "", mode)

    # if device does not support DFS, remove DFS channels from its capabilities
    if capab["dfs"]:
        return capab
    warn_printed = False
    for band, channels in capab["interfaces"]["radio_channels"].items():
        if not channels:
            continue
        if "5g" not in band:
            continue
        for channel in channels[:]:
            if is_channel_dfs(channel):
                if not warn_printed:
                    warn_printed = True
                    log.warning(
                        f"Removing DFS channels from supported radio channels for {capab['model_string']},"
                        f" as DFS flag is set to false. Review your model configuration file."
                    )
                channels.remove(channel)
        return capab


def is_channel_dfs(channel):
    """Simple check if channel is DFS.
    Args:
        channel: Channel ID.
    Returns:
        bool: True if channel is DFS, otherwise False is returned.
    """
    return 51 < channel < 145


def dict_deep_update(d, u):
    import collections.abc

    for k, v in u.items():
        # supported channels cannot be merged, due to 5G, 5GL, 5GU differences
        if k == "supported_channels":
            d[k] = v
            continue
        elif k == "include_file" and d.get(k):
            # For reservation we want to set include_file as a root config file
            continue
        if isinstance(v, collections.abc.Mapping):
            d[k] = dict_deep_update(d.get(k, {}), v)
        else:
            join = False
            if isinstance(v, list) and v:
                for value in v:
                    if not isinstance(value, collections.abc.Mapping) or not value.get("join"):
                        break
                else:
                    del value["join"]
                    join = True
            if not join:
                d[k] = v
            else:
                d[k].extend(v)
    return d


def decrypt_admin_password(encrypted_password):
    return Fernet(RANDOM_KEY).decrypt(encrypted_password.encode()).decode()


def update_config_with_admin_creds(config):
    if not config:
        return
    if enc_pwd := config.pop("admin_enc_pwd", None):
        config["admin_pwd"] = decrypt_admin_password(enc_pwd)
    if enc_uprise_pwd := config.pop("uprise_enc_pwd", None):
        config["uprise_pwd"] = decrypt_admin_password(enc_uprise_pwd)

    try:
        from lib.cloud.cloud import PROD_DEPLOYMENTS

        prod_deployments = PROD_DEPLOYMENTS
    except (ModuleNotFoundError, ImportError):
        prod_deployments = []

    if (dpl := config.get("deployment_id", "")) in prod_deployments:
        log.info(f"Using elevated credentials for {dpl}")
        cred_file = f"/etc/smokecreds/smoke{dpl}.json"
        try:
            with open(cred_file) as cred:
                info = json.load(cred)
                config.update(info)
                return
        except IOError:
            pass

        # the other option is to get them directly from Jenkins environments
        admin_user = os.environ.get("CLOUD_SMOKE_USER", None)
        admin_pwd = os.environ.get("CLOUD_SMOKE_PASS", None)
        if admin_user and admin_pwd:
            config["admin_user"] = admin_user
            config["admin_pwd"] = admin_pwd
            return
        log.error("Admin credentials not updated!")


def get_device_cfg(device_obj):
    return device_obj.lib.device.config


def get_uprise_network_creds(location_cfg, location_name, network_type="home"):
    uprise_location = get_uprise_loc_cfg(location_cfg, location_name)
    ssid, psk = None, None
    for uprise_network in uprise_location["Networks"]:
        if uprise_network["alias"] != network_type:
            continue
        ssid, psk = uprise_network["ssid"], uprise_network["key"]
        break
    return ssid, psk


def get_uprise_loc_cfg(location_cfg, location_name):
    target_uprise_location = {}
    for uprise_location in location_cfg["locations"]:
        if uprise_location["user_name"] != location_name:
            continue
        target_uprise_location = uprise_location
        break
    return target_uprise_location


class YamlLoader(yaml.SafeLoader):
    def __init__(self, stream):
        self._root = os.path.split(stream.name)[0]
        super(YamlLoader, self).__init__(stream)

    def include(self, node):
        paths = self.construct_scalar(node).split(",")
        out = None
        for path in paths:
            file_path = os.path.join(self._root, path.strip())
            with open(file_path, "r") as f:
                data = yaml.load(f, YamlLoader)
                if isinstance(data, dict):
                    if "ssh_gateway" in data:
                        data["include_file"] = os.path.abspath(file_path)
                    out = out or {}
                    out.update(data)
                elif isinstance(data, list):
                    out = out or []
                    out.extend(data)
                else:
                    return data
        return out

    def join(self, node):
        seq = self.construct_sequence(node)
        return "".join([str(i) for i in seq])


class YamlUpriseLoader(YamlLoader):
    @staticmethod
    def load_ustb_cfg(cfg_name: str, root_path: str) -> dict:
        ustb_cfg_path = os.path.join(root_path, f"{cfg_name}.yaml")
        with open(ustb_cfg_path, "r") as f:
            ustb_cfg = yaml.load(f, YamlLoader)
        return ustb_cfg

    @staticmethod
    def get_values_from_buffer(key: str, buffer_cfg: str) -> list:
        return re.findall(f"(?<={key}: ).+", buffer_cfg)

    def ustb_nodes(self, ustb_name):
        ustb_cfg = YamlUpriseLoader.load_ustb_cfg(ustb_name.value, self._root)
        uprise_locations = YamlUpriseLoader.get_values_from_buffer("user_name", self.buffer)
        assert len(uprise_locations) == len(ustb_cfg["Nodes"])
        uprise_base_node_name = "gw-uprise-{}"
        for i, ustb_node in enumerate(ustb_cfg["Nodes"]):
            ustb_node["name"] = uprise_base_node_name.format(i + 1)
            ustb_node["default_location"] = uprise_locations[i]
            ustb_node.pop("switch", None)
        return ustb_cfg["Nodes"]

    def ustb_clients(self, ustb_name):
        ustb_cfg = YamlUpriseLoader.load_ustb_cfg(ustb_name.value, self._root)
        uprise_locations = YamlUpriseLoader.get_values_from_buffer("user_name", self.buffer)
        uprise_isolation_groups = YamlUpriseLoader.get_values_from_buffer("isolation_group", self.buffer)
        uprise_clients = list()
        wifi_clients = [
            client for client in ustb_cfg["Clients"] if client.get("wifi") and client["type"] in ["linux", "rpi"]
        ]
        assert len(wifi_clients) >= len(uprise_locations)
        uprise_base_client_name = "w1-uprise-{}"
        for i, wifi_client in enumerate(wifi_clients):
            wifi_client["name"] = uprise_base_client_name.format(i + 1)
            wifi_client["default_location"] = uprise_locations[i]
            wifi_client["isolation_groups"] = uprise_isolation_groups[i]
            uprise_clients.append(wifi_client)
            if i + 1 == len(uprise_locations):
                break
        return uprise_clients

    def ustb_rpower(self, ustb_name):
        ustb_cfg = YamlUpriseLoader.load_ustb_cfg(ustb_name.value, self._root)
        ustb_nodes_map_to_uprise = dict(gw="gw-uprise-1", l1="gw-uprise-2", l2="gw-uprise-3")
        for ustb_rpower in ustb_cfg["rpower"]:
            uprise_aliases = list()
            for rpower_alias in ustb_rpower["alias"]:
                uprise_alias_name = ustb_nodes_map_to_uprise.get(rpower_alias["name"])
                if not uprise_alias_name:
                    continue
                rpower_alias["name"] = uprise_alias_name
                uprise_aliases.append(rpower_alias)
            if uprise_aliases:
                ustb_rpower["alias"] = uprise_aliases
        return ustb_cfg["rpower"]

    def ustb_ssh_gateway(self, ustb_name):
        ustb_cfg = YamlUpriseLoader.load_ustb_cfg(ustb_name.value, self._root)
        ssh_gw_config = ustb_cfg["ssh_gateway"]
        ssh_gw_config["location_file"] = os.path.join(self._root, f"{ustb_name.value}.yaml")
        return ssh_gw_config


YamlLoader.add_constructor("!include", YamlLoader.include)
YamlLoader.add_constructor("!join", YamlLoader.join)
YamlLoader.add_constructor("!ustb_nodes", YamlUpriseLoader.ustb_nodes)
YamlLoader.add_constructor("!ustb_clients", YamlUpriseLoader.ustb_clients)
YamlLoader.add_constructor("!ustb_rpower", YamlUpriseLoader.ustb_rpower)
YamlLoader.add_constructor("!ustb_ssh_gateway", YamlUpriseLoader.ustb_ssh_gateway)

# type checking for tb_config
_pass = TypedDict("_pass", {"pass": str})
ssh_gateway = TypedDict("ssh_gateway", {"user": str, "pass": str, "hostname": str})
node_host = TypedDict("node_host", {"user": str, "pass": str, "name": str})
client_host = TypedDict("client_host", {"user": str, "pass": str, "name": str})
rpower_alias = TypedDict("alias", {"name": str, "port": int})
switch_alias = TypedDict("alias", {"name": str, "port": int, "backhaul": int})


class TbConfig(TypedDict):
    email: str
    password: str
    user_name: str
    tb_maintainer: str
    capabilities: list
    profile: str
    ssh_gateway: ssh_gateway
    Nodes: list[Node]
    Clients: list[Client]
    Networks: list[Network]
    rpower: Rpower
    Switch: Switch
    group_name: list[str]
    wifi_check: dict[str, str]
    node_deploy_to: str
    client_deploy_to: str


class Node(TypedDict):
    name: str
    id: str
    model: str
    host: node_host
    switch: dict[str, list[str]]
    static_eth_client: str


class Client(TypedDict):
    name: str
    type: str
    host: client_host
    wifi: bool
    vlan: int
    bt: bool


class Network(TypedDict):
    ssid: str
    key: str
    alias: str


class Rpower(_pass):
    ipaddr: str
    user: str
    port: int
    alias: list[rpower_alias]


class Switch(_pass):
    name: str
    type: str
    ipaddr: str
    user: str
    port: int
    alias: list[switch_alias]
