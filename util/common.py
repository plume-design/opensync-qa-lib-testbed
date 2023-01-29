import os
import re
import pprint
import random
import urllib
import traceback
import subprocess
from time import time, sleep
from lib_testbed.generic.util.logger import log


BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", '..', ".."))
SKIP_RESULT = '[SKIP_RESULT]'


class JsonPrettyPrinter(pprint.PrettyPrinter):
    """Remove quotes from unicode"""
    def format(self, object, context, maxlevels, level):
        if isinstance(object, str):
            return object, True, False
        return pprint.PrettyPrinter.format(self, object, context, maxlevels, level)


def quote_cmd_string(cmd_string):
    return cmd_string \
        .replace('\\', '\\\\') \
        .replace('"', '\\"') \
        .replace('$', '\\$') \
        .replace('`', '\\`')


def get_git_revision():
    try:
        return subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'],
                                       stderr=subprocess.DEVNULL).decode('ascii').strip()
    except Exception:
        return ''


def fix_mac_address(address):
    """
    Fill MAC address parts with leading 0 if missing
    Args:
        address: (str) MAC address to be fixed, e.g '8:AA:C:3:ED:E'

    Returns: (str) Fixed MAc address, e.g '08:AA:0C:03:ED:0E'

    """
    return ':'.join([i.zfill(2) for i in address.split(':')])


def wait_for(predictable: callable, timeout: int, tick: float):
    start = time()

    condition = False
    ret = None
    while time() - start < timeout:
        if ret := predictable():
            condition = True
            break
        sleep(tick)

    return condition, ret


class DeviceCommon:
    @staticmethod
    def convert_model_name(model):
        if not model:
            return model
        return model.lower().replace(" ", "_").replace(".", "_").replace("-", "_")

    @staticmethod
    def get_device_capabilities_by_id(config, device_id):
        expected_device_cfg = next(filter(lambda device_cfg: device_cfg['id'] == device_id, config['Nodes']), {})
        return expected_device_cfg.get('capabilities', {})

    @staticmethod
    def get_gw_br_home(config):
        return config['Nodes'][0]['capabilities']['interfaces'].get('lan_bridge')

    @staticmethod
    def get_gw_dev_type(config):
        return config['Nodes'][0]['capabilities']['device_type']

    @staticmethod
    def get_device_hw_modes(device_capabilities_cfg):
        radio_hw_modes = device_capabilities_cfg.get('interfaces', {}).get('radio_hw_mode')
        assert radio_hw_modes, '"radio_hw_mode" is missed in the device capabilities config'
        radio_hw_modes = [hw_mode for hw_mode in radio_hw_modes.values() if hw_mode]
        return list(set(radio_hw_modes))

    @staticmethod
    def get_device_max_channel_widths(device_capabilities_cfg):
        max_channel_widths = device_capabilities_cfg.get('interfaces', {}).get('max_channel_width')
        assert max_channel_widths, '"max_channel_width" is missed in the device capabilities config'
        max_channel_widths = [channel_width for channel_width in max_channel_widths.values() if channel_width]
        return list(set(max_channel_widths))

    @staticmethod
    def get_all_supported_channels(device_capabilities_cfg, channel_type=int):
        radio_channels = device_capabilities_cfg.get('interfaces', {}).get('radio_channels')
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
                    results[name] = ''
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
    if hasattr(base_obj, "pytestmark"):
        obj.pytestmark = base_obj.pytestmark
    if hasattr(base_obj, "own_markers"):
        obj.own_markers = base_obj.own_markers
    if hasattr(base_obj, "_item"):
        obj.session_config = base_obj.base_session['config']


def is_jenkins():
    # JOB_NAME, BUILD_NUMBER and BUILD_URL are set by jenkins. Even inside docker these envs are propagated.
    if os.environ.get('JOB_NAME'):
        return True
    return False


def is_inside_infrastructure():
    try:
        inv_resp = urllib.request.urlopen("http://inventory-development.shared.us-west-2.aws.plume.tech:3005"
                                          "/explorer/", timeout=2).getcode()
    except Exception:
        inv_resp = 404
    return inv_resp == 200


def get_target_pytest_mark(all_marks, target_mark_name, arg_name=''):
    for pytest_mark in all_marks:
        if pytest_mark.name.startswith(target_mark_name):
            # Validate if expected pytest mark contains expected arguments
            # Helpfully for pytest marks which have the same name but different args
            if arg_name and arg_name not in pytest_mark.kwargs.keys():
                continue
            return pytest_mark
    return None


def generate_network_credentials(tb_config, network_id):
    tb_name = tb_config.get('user_name')
    assert tb_name, '"user_name" field is missed for tb-config'
    ssid = f'{network_id}-{tb_name}'[:32]
    # Guest zone should be always open
    password = f'{network_id}-12testtest'[:63] if network_id != 'guest' else ''
    return ssid, password


def get_parametrize_name(item):
    if '[' not in item.nodeid:
        return None
    return item.nodeid.split('[')[1].split(']')[0]


def generate_random_mac(mac_prefix):
    mac_prefix = [mac_prefix for mac_prefix in mac_prefix.split(':') if mac_prefix]
    while len(mac_prefix) < 6:
        mac_prefix.append(f'{random.randint(0, 255):02x}')
    new_mac = ':'.join(mac_prefix)
    log.info(f"Generated a new MAC address: {new_mac}")
    return new_mac


def mark_failed_recovery_attempt(tb_config):
    if not tb_config.get('failed_recovery_attempts'):
        tb_config.update(dict(failed_recovery_attempts=list()))
    tb_config['failed_recovery_attempts'].append(time())


def get_digits_value_from_text(value_to_take, text_response):
    regex_pattern = f'(?<={value_to_take}).\d+'
    value = re.search(regex_pattern, text_response)
    if not value:
        return 0
    return int(value.group())


def get_string_value_from_text(value_to_take, text_response):
    regex_pattern = f'(?<={value_to_take}).[A-Za-z]+'
    value = re.search(regex_pattern, text_response)
    if not value:
        return ''
    return value.group()


def get_full_ipv6_address(abbreviated_ipv6_addr):
    if '::' in abbreviated_ipv6_addr:
        ipv6_address = abbreviated_ipv6_addr.split('::')
        prefix_subnet_ids = ipv6_address[0].split(':')
        interface_ids = ipv6_address[-1].split(':')
        [interface_ids.insert(0, '0000') for _i in interface_ids if 4 > len(interface_ids)]
        address_to_parse = prefix_subnet_ids + interface_ids
    else:
        address_to_parse = abbreviated_ipv6_addr.split(':')
    # make sure leading zero exist
    ipv6_full_address = [value.zfill(4) for value in address_to_parse]
    return ':'.join(ipv6_full_address)


def get_iperf_ipv4_host_address(client_obj):
    match client_obj.lib.device_type:
        case 'Clients':
            match client_obj.nickname:
                case 'host':
                    ip_addr = client_obj.lib.config['wifi_check']['ipaddr']
                case 'remote_host':
                    ip_addr = client_obj.lib.config['iperf3_check']['hostname']
                case _:
                    ip_addr = client_obj.get_client_ips(client_obj.get_eth_iface().split("\n")[0])["ipv4"]
        case _:
            ip_addr = None
    return ip_addr


def get_rpower_devices(tb_config):
    rpower_aliases = [pod['alias'] for pod in tb_config.get('rpower', [])]
    rpower_devices = list()
    for rpower_alias in rpower_aliases:
        for rpower in rpower_alias:
            rpower_devices.append(rpower.get('name'))
    return rpower_devices


def unify_fw_version(version):
    """
    Replace any delimited in FW version string with '.'
    """
    parts = []
    for part in re.split(r'[.-]', version):
        if part.isdigit():
            parts.append(part)
    return ".".join(parts)
