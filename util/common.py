import os
import re
import ssl
import pprint
import random
import datetime
import urllib.request
import ipaddress
import traceback
import subprocess
import concurrent.futures
from copy import deepcopy
from functools import wraps
from time import time, sleep

import pytest
from packaging.version import parse, InvalidVersion
from pathlib import Path

from lib_testbed.generic.util.logger import log

BASE_DIR = Path(__file__).absolute().parents[3]
CACHE_DIR = BASE_DIR / ".framework_cache"
SKIP_RESULT = "[SKIP_RESULT]"
ALL_MARKERS_NAME = "all_markers"  # Variable assignation is done in lib/util/conftest_base.py
OVERWRITE_MARK_NAME = "overwrite_markers"
QASE_ID_MARKER_NAME = "qase_id"
QASE_TITLE_MARKER_NAME = "qase_title"
_DEFAULT_THREAD_EXECUTOR = concurrent.futures.ThreadPoolExecutor()
POSSIBLE_BANDS = ["2.4G", "5G", "5GL", "5GU", "6G"]


def skip_exception(*errors, log_traceback=True):
    """
    Decorator that accepts Exceptions: IOError, ValueError
    and wraps the whole function and skips those Exceptions.
    Usage:

    .. code-block:: py

        @skip_exception(ValueError, IOError)
        def do_whatever():
            ...
    """
    if not errors:
        raise SyntaxError("Explicit exceptions are required for the @skip_exception decorator.")

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except errors as e:
                if log_traceback:
                    log.exception("An error occurred")
                else:
                    log.error("An error occurred: %s", e)

        return wrapper

    return decorator


def threaded(f, executor=None) -> concurrent.futures.Future:
    """Decorator starting a select function in a thread.
    Returns a :py:class:`concurrent.futures.Future` object with
    task executed in a parallel executor, the default executor
    is :py:class:`concurrent.futures.ThreadPoolExecutor`.

    Usage:

    .. code-block:: py

        @threaded
        def my_concurrent_task(pod):
            res = pod.run("timeout 30 tcpdump -i br-home -vv ip6[40]==134", timeout=60)
            return res

        # this does not block, just runs the task in a thread:
        y = my_concurrent_task(gw)
        print(y)

        # this blocks waiting for the result:
        result = y.result()  # this is how to access the actual result
        print(result)
    """

    @wraps(f)
    def wrap(*args, **kwargs):
        return (executor or _DEFAULT_THREAD_EXECUTOR).submit(f, *args, **kwargs)

    return wrap


class JsonPrettyPrinter(pprint.PrettyPrinter):
    """Remove quotes from unicode"""

    def format(self, object, context, maxlevels, level):
        if isinstance(object, str):
            return object, True, False
        return pprint.PrettyPrinter.format(self, object, context, maxlevels, level)


def quote_cmd_string(cmd_string):
    return cmd_string.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")


def get_git_revision():
    try:
        return (
            subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL)
            .decode("ascii")
            .strip()
        )
    except Exception:
        return ""


def get_framework_version():
    try:
        with open(os.path.join(BASE_DIR, "version.txt")) as version_file:
            version = version_file.read()
            return version.strip()
    except Exception:
        return ""


def fix_mac_address(address):
    """
    Fill MAC address parts with leading 0 if missing
    Args:
        address: (str) MAC address to be fixed, e.g '8:AA:C:3:ED:E'

    Returns: (str) Fixed MAc address, e.g '08:AA:0C:03:ED:0E'

    """
    return ":".join([i.zfill(2) for i in address.split(":")])


def fill_ip_address(address):
    """
    Fill IP address parts with leading 0 if missing
    Args:
        address: (str) IP address to be fixed, e.g '192.168.1.10'

    Returns: (str) Fixed IP address, e.g '192.168.001.010'

    """
    return ".".join([i.zfill(3) for i in address.split(".")])


def wait_for(predictable: callable, timeout: int, tick: float, eval_condition: callable = lambda ret: True):
    start = time()
    condition = False
    ret = None
    while time() - start < timeout:
        try:
            if ret := predictable():
                if condition := eval_condition(ret):
                    break
        except Exception as e:
            ret = e
        sleep(tick)

    return condition, ret


def compare_fw_versions(fw_version: str, reference_fw: str, condition: str = ">") -> bool | None:
    """Compare two FW version and returns True if fw_version is newer than reference_fw.
    It is possible to compare version with the >, <, >=, <= or == conditions.
    """
    try:
        firmware_version = re.search(r"(\d+\.\d+\.\d+([-.]\d+)?)", fw_version).group().replace("-", ".")
    except AttributeError:
        firmware_version = fw_version
    try:
        reference_fw_version = re.search(r"(\d+\.\d+\.\d+([-.]\d+)?)", reference_fw).group().replace("-", ".")
    except AttributeError:
        reference_fw_version = reference_fw
    try:
        match condition:
            case ">":
                return parse(firmware_version) > parse(reference_fw_version)
            case "<":
                return parse(firmware_version) < parse(reference_fw_version)
            case ">=":
                return parse(firmware_version) >= parse(reference_fw_version)
            case "<=":
                return parse(firmware_version) <= parse(reference_fw_version)
            case "==":
                return parse(firmware_version) == parse(reference_fw_version)
            case _:
                raise ValueError("Comparison condition must either be '>', '<', '>=' or '=='.")
    except InvalidVersion:
        return None


class DeviceCommon:
    @staticmethod
    def convert_model_name(model):
        if not model:
            return model
        return model.lower().replace(" ", "_").replace(".", "_").replace("-", "_")

    @staticmethod
    def get_device_capabilities_by_id(config, device_id):
        expected_device_cfg = next(filter(lambda device_cfg: device_cfg["id"] == device_id, config["Nodes"]), {})
        return expected_device_cfg.get("capabilities", {})

    @staticmethod
    def get_gw_br_home(config):
        return config["Nodes"][0]["capabilities"]["interfaces"].get("lan_bridge")

    @staticmethod
    def get_gw_dev_type(config):
        return config["Nodes"][0]["capabilities"]["device_type"]

    @staticmethod
    def get_device_hw_modes(device_capabilities_cfg):
        radio_hw_modes = device_capabilities_cfg.get("interfaces", {}).get("radio_hw_mode")
        assert radio_hw_modes, '"radio_hw_mode" is missed in the device capabilities config'
        radio_hw_modes = [hw_mode for hw_mode in radio_hw_modes.values() if hw_mode]
        return list(set(radio_hw_modes))

    @staticmethod
    def get_device_max_channel_widths(device_capabilities_cfg):
        max_channel_widths = device_capabilities_cfg.get("interfaces", {}).get("max_channel_width")
        assert max_channel_widths, '"max_channel_width" is missed in the device capabilities config'
        max_channel_widths = [channel_width for channel_width in max_channel_widths.values() if channel_width]
        return list(set(max_channel_widths))

    @staticmethod
    def get_all_supported_channels(device_capabilities_cfg, channel_type=int):
        radio_channels = device_capabilities_cfg.get("interfaces", {}).get("radio_channels")
        assert radio_channels, '"radio_channels" is missed in the device capabilities config'
        all_supported_channels = list()
        for channel_set in radio_channels.values():
            if not channel_set:
                continue
            all_supported_channels.extend(channel_set)
        # set expected channel var type
        all_supported_channels = [channel_type(channel) for channel in all_supported_channels]
        return all_supported_channels


class Results:
    @staticmethod
    def get_sorted_results(results, devices, skip_exception=False):
        sorted_results = []
        names = [device.get_name() for device in devices]
        for name in names:
            if name not in results:
                error = f"Missing '{name}' in results: {results.keys()}"
                if skip_exception:
                    log.error(error)
                    results[name] = ""
                else:
                    raise Exception(error)
            # if skip_exception and Results.is_ssh_exception(results[name]):
            #     log.info(f"Skipping SshException for '{name}'")
            #     results[name] = ''
            sorted_results.append(results[name])
        return sorted_results

    @staticmethod
    def call_method(attr, self_obj, not_callable, device, results_dict, *args, **kwargs):
        if not_callable:
            result = attr
        else:
            try:
                result = attr(*args, **kwargs)
            except Exception as e:
                except_str = traceback.format_exc()
                e.args += (except_str,)
                result = e

        # prevent wrapped_class from becoming unwrapped
        if result == device:
            result = self_obj
        results_dict.update({device.get_name(): result})


def copy_obj_params(base_obj, obj):
    if hasattr(base_obj, ALL_MARKERS_NAME):
        obj.all_markers = base_obj.all_markers
    if hasattr(base_obj, "own_markers"):
        obj.own_markers = base_obj.own_markers
    if hasattr(base_obj, "_item"):
        obj.session_config = base_obj.base_session["config"]
    if hasattr(base_obj, "request"):
        obj.request = base_obj.request


def is_jenkins():
    # JOB_NAME, BUILD_NUMBER and BUILD_URL are set by jenkins. Even inside docker these envs are propagated.
    if os.environ.get("JOB_NAME"):
        return True
    return False


def is_service_accessible(service):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        service_resp = urllib.request.urlopen(service, timeout=2, context=ctx).getcode()
    except Exception:
        service_resp = 404
    return service_resp == 200


def is_inside_infrastructure():
    return is_service_accessible("https://inventory-api.global.plume.tech/explorer/")


def get_target_pytest_mark(all_marks, target_mark_name, arg_name=""):
    for pytest_mark in all_marks:
        if pytest_mark.name.startswith(target_mark_name):
            # Validate if expected pytest mark contains expected arguments
            # Helpfully for pytest marks which have the same name but different args
            if arg_name and arg_name not in pytest_mark.kwargs.keys():
                continue
            return pytest_mark
    return None


def generate_network_credentials(tb_config, network_id):
    tb_name = tb_config.get("user_name")
    assert tb_name, '"user_name" field is missed for tb-config'
    ssid = f"{network_id}-{tb_name}"[:32]
    # Guest zone should be always open
    password = f"{network_id}-{tb_config.get('password', '')}"[:63] if network_id != "guest" else ""
    return ssid, password


def generate_mac_address(mac_prefix=None):
    mac_prefix = ["dc", "a6"] if not mac_prefix else mac_prefix
    while len(mac_prefix) < 6:
        mac_prefix.append(f"{random.randint(0, 255):02x}")
    new_mac = ":".join(mac_prefix)
    return new_mac


def get_parametrize_name(item):
    if "[" not in item.nodeid:
        return None
    return item.nodeid.split("[")[1].split("]")[0]


def generate_random_mac(mac_prefix):
    mac_prefix = [mac_prefix for mac_prefix in mac_prefix.split(":") if mac_prefix]
    while len(mac_prefix) < 6:
        mac_prefix.append(f"{random.randint(0, 255):02x}")
    new_mac = ":".join(mac_prefix)
    log.info(f"Generated a new MAC address: {new_mac}")
    return new_mac


def mark_failed_recovery_attempt(tb_config):
    if not tb_config.get("failed_recovery_attempts"):
        tb_config.update(dict(failed_recovery_attempts=list()))
    tb_config["failed_recovery_attempts"].append(time())


def get_digits_value_from_text(value_to_take, text_response):
    regex_pattern = rf"(?<={value_to_take}).\d+"
    value = re.search(regex_pattern, text_response)
    if not value:
        return 0
    return int(value.group())


def get_string_value_from_text(value_to_take, text_response):
    regex_pattern = rf"(?<={value_to_take}).[A-Za-z]+"
    value = re.search(regex_pattern, text_response)
    if not value:
        return ""
    return value.group()


def get_full_ipv6_address(abbreviated_ipv6_addr):
    return ipaddress.IPv6Address(abbreviated_ipv6_addr).exploded


def get_iperf_ipv4_host_address(client_obj):
    match client_obj.lib.device_type:
        case "Clients":
            match client_obj.nickname:
                case "host":
                    ip_addr = client_obj.lib.config["wifi_check"]["ipaddr"]
                case "remote_host":
                    ip_addr = client_obj.lib.config["iperf3_check"]["hostname"]
                case _:
                    ip_addr = client_obj.get_client_ips(client_obj.get_eth_iface().split("\n")[0])["ipv4"]
        case _:
            ip_addr = None
    return ip_addr


def get_rpower_devices(tb_config):
    rpower_aliases = [pod["alias"] for pod in tb_config.get("rpower", [])]
    rpower_devices = list()
    for rpower_alias in rpower_aliases:
        for rpower in rpower_alias:
            rpower_devices.append(rpower.get("name"))
    return rpower_devices


def unify_fw_version(version):
    """
    Replace any delimited in FW version string with '.'
    """
    parts = []
    for part in re.split(r"[.-]", version):
        if part.isdigit():
            parts.append(part)
    return ".".join(parts)


def is_function_parameterized(item):
    if not hasattr(item, "callspec"):
        return False
    from _pytest.scope import Scope

    parameterized_scopes = list(set(item.callspec._arg2scope.values()))

    # Function parametrization only
    if len(parameterized_scopes) == 1 and Scope("function") in parameterized_scopes:
        return True
    return False


def get_test_module_name(item) -> str:
    # Get cls name for class approach for fixtures use module name
    test_module_name = item.cls.__name__ if item.cls else item.module.__name__
    return test_module_name


def get_node_config_by(tb_cfg: dict, name: str = "", node_id: str = "", idx: int = None) -> dict:
    node_cfg = dict()
    if name:
        node_cfg = next(filter(lambda node: node.get("name", "") == name, tb_cfg["Nodes"]), {})
    elif node_id:
        node_cfg = next(filter(lambda node: node.get("id", "") == node_id, tb_cfg["Nodes"]), {})
    elif idx is not None:
        node_cfg = tb_cfg["Nodes"][idx]
    return node_cfg


def get_client_config_by(tb_cfg: dict, name: str = "", idx: int = None) -> dict:
    client_cfg = dict()
    if name:
        client_cfg = next(filter(lambda node: node.get("name", "") == name, tb_cfg["Clients"]), {})
    elif idx is not None:
        client_cfg = tb_cfg["Clients"][idx]
    return client_cfg


def get_module_parameterization_id(item, add_brackets: bool = False, skip_func_param: bool = True) -> str:
    param_id = ""
    if not hasattr(item, "callspec"):
        return param_id
    from _pytest.scope import Scope

    # Skip setting parameterization id for function parameterization scopes
    parameterization_ids = list()
    for _param_id, param_scope in zip(item.callspec._idlist, item.callspec._arg2scope.values()):
        if skip_func_param and (Scope("function") == param_scope):
            continue
        parameterization_ids.append(_param_id)
    param_id = "-".join(parameterization_ids)
    if param_id and add_brackets:
        param_id = f"[{param_id}]"
    return param_id if param_id else ""


def is_ipv6_used(all_markers: list) -> True:
    wan_connection = get_target_pytest_mark(all_markers, "wan_connection")
    wan_vlan = getattr(wan_connection, "kwargs", {}).get("vlan_id", 200)
    return 201 <= wan_vlan <= 206


def get_modified_params(item):
    params = deepcopy(item.callspec.params) if hasattr(item, "callspec") else {}
    id_list = deepcopy(item.callspec._idlist) if hasattr(item, "callspec") else []
    mod_params = deepcopy(params)
    if len(id_list) == len(params):
        for i, (param_key, param_value) in enumerate(mod_params.items()):
            params[param_key] = id_list[i]
    return params


def get_qase_id(item: pytest.Item) -> int | None:
    """Get qase-id from the pytest item."""
    # Single item can have only one qase-id
    qase_id_marker = item.get_closest_marker(QASE_ID_MARKER_NAME)
    if not qase_id_marker:
        return None
    return qase_id_marker.kwargs.get("id")


def get_test_title(item: pytest.Item) -> str:
    qase_title_marker = item.get_closest_marker(QASE_TITLE_MARKER_NAME)
    if not qase_title_marker:
        return ""
    return qase_title_marker.kwargs.get("title")


def get_datetime_iso(
    timezone: datetime.timezone = datetime.UTC,
    tz_offset: bool = True,
    zulu_offset: bool = False,
    timedelta: datetime.timedelta = None,
) -> str:
    """Get datetime iso format based on provided timezone - by default UTC."""
    datetime_now = datetime.datetime.now(timezone)
    # Some of the cloud API doesn't support time zone offset within isoformat():
    # with offset: 2024-01-29T07:39:47.875566+00:00
    # without offset: 2024-01-29T07:39:47.875566
    # Add possibility to remove timezone info to support these API endpoints.
    if not tz_offset:
        datetime_now = datetime_now.replace(tzinfo=None)
    if timedelta:
        datetime_now = datetime_now + timedelta
    date_time_iso = datetime_now.isoformat()
    # Some of the cloud API needs Zulu offset
    if timezone == datetime.UTC and zulu_offset:
        date_time_iso += "Z"
    return date_time_iso
