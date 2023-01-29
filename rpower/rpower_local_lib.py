# IMPORTANT: We need to keep it as one of our customer do not use our rpi-server FW

import requests
import xmltodict
import time
from html.parser import HTMLParser
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.logger import log

RPOWER_DEVICE = 'rpower'
RPOWER_DEVICE_IPDADDR = 'ipaddr'
RPOWER_DEVICE_PORT = 'port'
RPOWER_DEVICE_USER = 'user'
RPOWER_DEVICE_PASS = 'pass'
RPOWER_DEVICE_ALIAS = 'alias'
RPOWER_DEVICE_ALIAS_NAME = 'name'
RPOWER_DEVICE_ALIAS_PORT = 'port'
TBCFG_NODES = 'Nodes'

ENV_RPOWER_CONFIG = 'RPOWER_CONFIG'

RPOWER_DEVICE_ENERGENIE = 'energenie'
ENERGENIE_URL = 'http://{0}:{1}@{2}:{3}/'

RPOWER_DEVICE_WPS = 'wps'
WPS_URL = 'http://{0}:{1}@{2}:{3}/'

RPOWER_DEVICE_CYBERPOWER = 'cyberpower'
CYBERPOWER_TOOL = '/home/plume/cyberpower'

RPOWER_DEVICE_FAKE = 'fake'


_rpower_aliases = {}
__rpower_config = None
_rpower_all_device_names = []
_rpower_node_names = []
_rpower_client_names = []


def select_nodes(return_values, sel_fcn=lambda y: y[0] == 0):
    return [node for node, value in list(return_values.items()) if sel_fcn(value)]


def to_list(obj):
    if not hasattr(obj, "__iter__"):
        obj = [obj]
    return obj


class MyHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.cursor = False
        self.my_data = []

    def error(self, message):
        pass

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.cursor = True

    def handle_data(self, data):
        if self.cursor:
            if 'XML' not in data and data.strip():
                self.my_data.append(data.strip())


class PowerController:
    def on(self, port_no):
        raise NotImplementedError()

    def off(self, port_no):
        raise NotImplementedError()

    def status(self, port_no):
        raise NotImplementedError()

    def model(self, **kwargs):
        raise NotImplementedError()

    def version(self, **kwargs):
        raise NotImplementedError()

    def get_request_timestamp(self, device_name):
        raise NotImplementedError()

    def get_last_request_time(self, device_name):
        last_request_time = self.get_request_timestamp(device_name)
        if not last_request_time:
            return None
        return time.time() - last_request_time


class EnergeniePowerController(PowerController):
    request_timestamp = {}

    def __init__(self, address, port, user, passwd, url=ENERGENIE_URL, ports=8):
        self.address = address
        self.port = port
        self.url = url
        self.user = user
        self.passwd = passwd
        self.ports = ports

    def execute_request(self, request):
        url = self.url.format(self.user, self.passwd, self.address, self.port) + request
        ret_val = 1
        err_str = ''
        std_out = ''
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                ret_val = response.status_code
            else:
                std_out = response.content.decode()
                ret_val = 0

        except Exception as e:
            err_str = str(e)
            std_out = 'UNKNOWN'

        return [ret_val, std_out, err_str]

    def on(self, ports):
        ports = to_list(ports)
        mask = ['0'] * self.ports
        for port in ports:
            mask[port - 1] = '1'
        req = f'ons.cgi?led={"".join(mask)}'
        ret_val = self.execute_request(req)
        # validate if port state is according to the request
        if ret_val[0]:
            return [ret_val for port in ports]
        # 8 sec is the max default port delay
        timeout = time.time() + 15
        while time.time() < timeout:
            all_states = self.status(ports)
            states = set([_state[1] for _state in all_states])
            if len(states) == 1 and states.pop() == 'ON':
                return [ret_val for port in ports]
            time.sleep(3)

        out = []
        for port, status in zip(ports, all_states):
            ret_code = 0 if status[1] == 'ON' else 1
            ret_stdout = ret_val[1] if status[1] == 'ON' else ''
            ret_stderr = '' if status[1] == 'ON' else f'INCORRECT PORT {port} STATE'
            out.append([ret_code, ret_stdout, ret_stderr])
        return out

    def off(self, ports):
        ports = to_list(ports)
        mask = ['0'] * self.ports
        for port in ports:
            mask[port - 1] = '1'
        req = f'offs.cgi?led={"".join(mask)}'
        ret_val = self.execute_request(req)
        # validate if port state is according to the request
        if ret_val[0]:
            return [ret_val for port in ports]
        # 8 sec is the max default port delay
        timeout = time.time() + 15
        while time.time() < timeout:
            all_states = self.status(ports)
            states = set([_state[1] for _state in all_states])
            if len(states) == 1 and states.pop() == 'OFF':
                return [ret_val for port in ports]
            time.sleep(1)

        out = []
        for port, status in zip(ports, all_states):
            ret_code = 0 if status[1] == 'OFF' else 1
            ret_stdout = ret_val[1] if status[1] == 'OFF' else ''
            ret_stderr = '' if status[1] == 'OFF' else f'INCORRECT PORT {port} STATE'
            out.append([ret_code, ret_stdout, ret_stderr])
        return out

    def status(self, ports):
        req = 'status.xml'
        resp = self.execute_request(req)
        if resp[0]:
            return [resp for port in ports]
        respxml = xmltodict.parse(resp[1])
        status = respxml['response']['pot0'].split(',')[10:18]
        retval = [[0, "ON" if status[port - 1] == '1' else "OFF", ""] for port in ports]
        return retval

    def model(self, **kwargs):
        req = 'system.htm'
        resp = self.execute_request(req)
        parser = MyHtmlParser()
        parser.feed(resp[1])
        stop = False
        for data in parser.my_data:
            if stop:
                return [0, data, '']
            if 'model' in data.lower():
                stop = True
        return [1, '', 'UNKNOWN']

    def version(self, **kwargs):
        req = 'system.htm'
        resp = self.execute_request(req)
        parser = MyHtmlParser()
        parser.feed(resp[1])
        stop = False
        for data in parser.my_data:
            if stop:
                return [0, data, '']
            if 'firmware' in data.lower():
                stop = True
        return [1, '', 'UNKNOWN']

    @staticmethod
    def set_last_request_time(device_name):
        WPSPowerController.request_timestamp[device_name] = time.time()

    def get_request_timestamp(self, device_name):
        return WPSPowerController.request_timestamp.get(device_name)


class WPSPowerController(PowerController):
    request_timestamp = {}

    def __init__(self, address, port, user, passwd, url=WPS_URL, ports=8):
        self.address = address
        self.port = port
        self.url = url
        self.user = user
        self.passwd = passwd
        self.ports = ports

    def execute_request(self, request, retry=3, **kwargs):
        url = self.url.format(self.user, self.passwd, self.address, self.port) + request
        ret_val = 1
        err_str = ''
        std_out = ''
        skip_logging = kwargs.pop('skip_logging', False)
        while retry > 0:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code != 200:
                    ret_val = response.status_code
                else:
                    std_out = response.content.decode()
                    err_str = ''
                    ret_val = 0
                break
            except Exception as e:
                if not skip_logging:
                    log.warn(f'Unable to execute request: {url}')
                err_str = str(e)
            time.sleep(0.5)
            retry -= 1
        return [ret_val, std_out, err_str]

    def on(self, ports):
        resp = []
        for port in ports:
            out = self.execute_request(f'outlet?{port}=ON')
            out[1] = 'Success!' if not out[0] else out[1]
            resp.append(out)

        # validate if port state is according to the request
        timeout = time.time() + 15
        while time.time() < timeout:
            all_states = self.status(ports)
            states = set([_state[1] for _state in all_states])
            if len(states) == 1 and states.pop() == 'ON':
                return resp
            time.sleep(1)

        ret = []
        for port, status, _resp in zip(ports, all_states, resp):
            ret_code = 0 if status[1] == 'ON' else 1
            ret_stdout = _resp[1] if status[1] == 'ON' else ''
            ret_stderr = '' if status[1] == 'ON' else f'INCORRECT PORT {port} STATE'
            ret.append([ret_code, ret_stdout, ret_stderr])
        return ret

    def off(self, ports):
        resp = []
        for port in ports:
            out = self.execute_request(f'outlet?{port}=OFF')
            out[1] = 'Success!' if not out[0] else out[1]
            resp.append(out)

        # validate if port state is according to the request
        timeout = time.time() + 15
        while time.time() < timeout:
            all_states = self.status(ports)
            states = set([_state[1] for _state in all_states])
            if len(states) == 1 and states.pop() == 'OFF':
                return resp
            time.sleep(1)

        ret = []
        for port, status, _resp in zip(ports, all_states, resp):
            ret_code = 0 if status[1] == 'OFF' else 1
            ret_stdout = _resp[1] if status[1] == 'OFF' else ''
            ret_stderr = '' if status[1] == 'OFF' else f'INCORRECT PORT {port} STATE'
            ret.append([ret_code, ret_stdout, ret_stderr])
        return ret

    def status(self, ports):
        req = 'index.htm'
        val = None
        resp = self.execute_request(req)[1].split(' ')
        for token in resp:
            if token.find('state=') >= 0:
                val = int(token.split('=')[1], 16)
        if val is None:
            return [[1, "", f"Could not read {port} state"] for port in ports]
        return [[0, "ON" if (val >> (port - 1)) & 0x01 else "OFF", ""] for port in ports]

    def model(self, **kwargs):
        req = 'support.htm'
        resp = self.execute_request(req, **kwargs)
        parser = MyHtmlParser()
        parser.feed(resp[1])
        for data in parser.my_data:
            if 'controller:' in data.lower():
                return [0, 'DLI', '']
        return [1, '', 'UNKNOWN']

    def version(self, **kwargs):
        req = 'support.htm'
        resp = self.execute_request(req)
        parser = MyHtmlParser()
        parser.feed(resp[1])
        stop = False
        for data in parser.my_data:
            if stop:
                return [0, data.split(' ')[0], '']
            if 'firmware version' in data.lower():
                stop = True
        return [1, '', 'UNKNOWN']

    @staticmethod
    def set_last_request_time(device_name):
        WPSPowerController.request_timestamp[device_name] = time.time()

    def get_request_timestamp(self, device_name):
        return WPSPowerController.request_timestamp.get(device_name)


class CyberPowerController(PowerController):
    request_timestamp = {}

    def __init__(self, address, port, user, passwd):
        global _rpower_config
        from lib_testbed.generic.client.client import Clients
        from lib_testbed.generic.util.config import init_fixed_host_clients
        config = {"ssh_gateway": {
            "user": _rpower_config.get('ssh_gateway', {}).get('user', 'plume'),
            "pass": _rpower_config.get('ssh_gateway', {}).get('pass', 'plume'),
            "port": _rpower_config.get('ssh_gateway', {}).get('port', 22),
            "hostname": address
        }}
        init_fixed_host_clients(config)
        kwargs = {'config': config, 'multi_obj': True, 'type': 'rpi', 'nicknames': ['host'], 'skip_logging': True}
        clients_obj = Clients(**kwargs)
        clients_api = clients_obj.resolve_obj(**kwargs)
        self.address = address
        self.server_lib = clients_api.lib
        self.cyberpower = "/home/plume/cyberpower"

    def execute_request(self, request, **kwargs):
        ret = self.server_lib.run_command(request, **kwargs)[0]
        self.server_lib.strip_stdout_result(ret, **kwargs)
        return ret

    def on(self, ports):
        resp = []
        for port in ports:
            ret = self.execute_request(f"{CYBERPOWER_TOOL} set-state {port} on")
            resp.append(ret)
        return resp

    def off(self, ports):
        resp = []
        for port in ports:
            ret = self.execute_request(f"{CYBERPOWER_TOOL} set-state {port} off")
            resp.append(ret)
        return resp

    def status(self, ports):
        resp = []
        for port in ports:
            ret = self.execute_request(f"{CYBERPOWER_TOOL} get-state {port}")
            resp.append(ret)
        return resp

    def model(self, **kwargs):
        return self.execute_request(f"{CYBERPOWER_TOOL} model", **kwargs)

    def version(self, **kwargs):
        return self.execute_request(f"{CYBERPOWER_TOOL} version", **kwargs)

    @staticmethod
    def set_last_request_time(device_name):
        WPSPowerController.request_timestamp[device_name] = time.time()

    def get_request_timestamp(self, device_name):
        return WPSPowerController.request_timestamp.get(device_name)


class FakePowerController(PowerController):
    request_timestamp = {}

    def __init__(self, address, port, user, passwd, url=None, ports=8):
        self.state = [0] * ports
        return

    def on(self, ports):
        for port in ports:
            self.state[port - 1] = 1
        return [[0, "Fake port! ON ", ""] for port in ports]

    def off(self, ports):
        for port in ports:
            self.state[port - 1] = 0
        return [[0, "Fake port! OFF", ""] for port in ports]

    def status(self, ports):
        return [[0, "ON" if (self.state[port - 1] & 0x01) else "OFF", ""] for port in ports]

    def model(self, **kwargs):
        return [0, 'Fake PDU', '']

    def version(self, **kwargs):
        return [0, '1.0.1', '']

    @staticmethod
    def set_last_request_time(device_name):
        WPSPowerController.request_timestamp[device_name] = time.time()

    def get_request_timestamp(self, device_name):
        return WPSPowerController.request_timestamp.get(device_name)


def _get_power_controller_dict(nodes):
    power_controllers = {}
    for node in nodes:
        if node in _rpower_aliases:
            power_controller, port = _rpower_aliases[node]
            if power_controller not in power_controllers:
                power_controllers[power_controller] = [[node], [port]]
            else:
                power_controllers[power_controller][0].append(node)
                power_controllers[power_controller][1].append(port)
    return power_controllers


def _get_power_controller_list():
    power_controllers = []
    for alias in _rpower_aliases:
        pdu = _rpower_aliases[alias][0]
        if pdu not in power_controllers:
            power_controllers.append(pdu)
    return power_controllers


def get_last_request_time(nodes):
    ret_val = {}
    for node in nodes:
        ret_val[node] = None

    power_controllers = _get_power_controller_dict(nodes)
    for power_controller, (pnodes, _ports) in power_controllers.items():
        for node in pnodes:
            last_request = power_controller.get_last_request_time(node)
            ret_val[node] = last_request
    return ret_val


def rpower_on(nodes):
    'Turn device on'
    ret_val = {}
    power_controllers = _get_power_controller_dict(nodes)
    for power_controller, (pnodes, ports) in power_controllers.items():
        ret = power_controller.on(ports)
        for node in pnodes:
            ret_val[node] = ret[pnodes.index(node)]
            power_controller.set_last_request_time(node)
    return ret_val


def rpower_off(nodes):
    'Turn device off'
    ret_val = {}
    power_controllers = _get_power_controller_dict(nodes)
    for power_controller, (pnodes, ports) in power_controllers.items():
        ret = power_controller.off(ports)
        for node in pnodes:
            ret_val[node] = ret[pnodes.index(node)]
            power_controller.set_last_request_time(node)
    return ret_val


def rpower_cycle(nodes, timeout=5):
    'Power cycle the device'
    state_off = rpower_off(nodes)
    if any(state_off[node][0] for node in state_off):
        return state_off
    time.sleep(int(timeout))
    return rpower_on(nodes)


def rpower_status(nodes):
    'Get device power status'
    ret_val = {}
    power_controllers = _get_power_controller_dict(nodes)
    for power_controller, (pnodes, ports) in power_controllers.items():
        ret = power_controller.status(ports)
        for node in pnodes:
            ret_val[node] = ret[pnodes.index(node)]
    return ret_val


def rpower_model():
    'Get device power model'
    ret_val = {}
    power_controllers = _get_power_controller_list()
    for power_controller in power_controllers:
        ret = power_controller.model()
        ret_val[power_controller.address] = ret
    return ret_val


def rpower_version():
    'Get device power model'
    ret_val = {}
    power_controllers = _get_power_controller_list()
    for power_controller in power_controllers:
        ret = power_controller.version()
        ret_val[power_controller.address] = ret
    return ret_val


def rpower_get_all_devices():
    return _rpower_all_device_names


def rpower_get_client_devices():
    return _rpower_client_names


def rpower_get_nodes_devices():
    return _rpower_node_names


def get_config_item(container, key):
    if key not in container:
        raise OpenSyncException('Power control unit not properly configured',
                                f'Check rpower {key} settings in locations config')

    return container[key]


def get_node_names(config):
    node_names = [node.get('name') for node in config.get('Nodes', [])]
    return node_names


def get_client_names(config):
    node_names = [node.get('name') for node in config.get('Clients', [])]
    return node_names


def rpower_init_config(config, **kwargs):
    global _rpower_config
    global _rpower_all_device_names
    global _rpower_node_names
    global _rpower_client_names
    global _rpower_aliases
    _rpower_config = config

    if RPOWER_DEVICE not in _rpower_config:
        return

    _rpower_all_device_names = []

    for rpower in _rpower_config[RPOWER_DEVICE]:
        for node in rpower[RPOWER_DEVICE_ALIAS]:
            try:
                _rpower_all_device_names.append(node[RPOWER_DEVICE_ALIAS_NAME])
            except KeyError:
                raise Exception('Rpower name not set in location config (rpower section)')

    node_names = get_node_names(config)
    _rpower_node_names = [node for node in node_names if node in _rpower_all_device_names]
    client_names = get_client_names(config)
    _rpower_client_names = [client for client in client_names if client in _rpower_all_device_names]

    _rpower_aliases = {}
    for device in _rpower_config[RPOWER_DEVICE]:
        ipaddr = get_config_item(device, RPOWER_DEVICE_IPDADDR)
        port = get_config_item(device, RPOWER_DEVICE_PORT)
        user = get_config_item(device, RPOWER_DEVICE_USER)
        passwd = get_config_item(device, RPOWER_DEVICE_PASS)

        if 'type' in device:
            match device['type']:
                case 'fake':
                    power_controller = FakePowerController(ipaddr, port, user, passwd)
                case 'wps' | 'dli':
                    power_controller = WPSPowerController(ipaddr, port, user, passwd)
                case 'cyberpower':
                    power_controller = CyberPowerController(ipaddr, port, user, passwd)
                case 'energenie':
                    power_controller = EnergeniePowerController(ipaddr, port, user, passwd)
                case _:
                    raise Exception(f"Unknown PDU type in the config: {device['type']}")
        else:
            for pdu in [WPSPowerController(ipaddr, port, user, passwd),
                        CyberPowerController(ipaddr, port, user, passwd),
                        EnergeniePowerController(ipaddr, port, user, passwd)]:
                model = pdu.model(retry=1, skip_logging=True, timeout=5)
                if model[0] == 0:
                    power_controller = pdu
                    break
            else:
                raise Exception("Cannot detect remote PDU model")

        for alias in get_config_item(device, RPOWER_DEVICE_ALIAS):
            name = get_config_item(alias, RPOWER_DEVICE_ALIAS_NAME)
            port = int(get_config_item(alias, RPOWER_DEVICE_ALIAS_PORT))

            _rpower_aliases[name] = (power_controller, port)
