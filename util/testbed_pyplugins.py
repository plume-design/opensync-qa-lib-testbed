import re
import queue
import pytest
import threading
import datetime
import sys
import traceback

from copy import deepcopy
from lib_testbed.generic.util import config
from lib_testbed.generic.util.logger import log, LogCatcher
from lib_testbed.generic.pod.pod import Pods
from lib_testbed.generic.client.client import Clients


class PyTemperatureMonitorPlugin:
    def __init__(self, config_name):
        self.config_name = config_name
        self.pods = None
        self.clients = None
        self.monitor_main_q = queue.Queue()
        self.monitor_t = None

    @pytest.fixture(scope="session", autouse=True)
    def temperature_monitor_fixture(self, request):
        cfg = config.load_tb_config(self.config_name, skip_deployment=True) \
            if not hasattr(pytest.mark._config, 'tb_config') else pytest.mark._config.tb_config
        cfg = deepcopy(cfg)
        # Consider OSRT setups only
        if not re.search('osrt', str(cfg.get('capabilities', '')), re.IGNORECASE):
            # nothing to monitor, exit
            yield
            return
        # Monitor only our node models
        nodes = {}
        for node in cfg.get("Nodes", []):
            hostname = node.get('host', {}).get('name')
            if node.get('model', '').startswith(('plume_pod', 'pp')) and hostname and hostname not in nodes:
                nodes[hostname] = node
        clients = {}
        for client in cfg.get("Clients", []):
            hostname = client.get('host', {}).get('name')
            if hostname and hostname not in clients:
                clients[hostname] = client
        if not nodes:
            # nothing to monitor, exit
            yield
            return
        cfg["Nodes"] = list(nodes.values())
        cfg["Clients"] = list(clients.values())
        kwargs = {'config': cfg, 'multi_obj': True, 'skip_logging': True}
        pods_obj = Pods(**kwargs)
        self.pods = pods_obj.resolve_obj(**kwargs)
        clients_obj = Clients(**kwargs)
        self.clients = clients_obj.resolve_obj(**kwargs)
        self.start_monitoring()
        yield
        self.stop_monitoring()
        LogCatcher.attach_to_allure([[temp_log_catcher.get_logger()]])
        config.remove_ssh_key_files(cfg)

    def start_monitoring(self):
        self.monitor_t = threading.Thread(target=self.monitor_temperature, name="monitor_thread")
        self.monitor_t.start()
        log.info(f"Monitoring temperature for {self.pods.get_nicknames()} pods")
        log.info(f"Monitoring temperature for {self.clients.get_nicknames()} clients")

    def stop_monitoring(self):
        log.info('Stopping testbed temperature monitoring\n')
        if self.monitor_t and self.monitor_t.is_alive():
            self.monitor_main_q.put("STOP")
            self.monitor_t.join()
        log.info(f'Monitor temperature thread -> "{self.monitor_t.getName()}" current state == '
                 f'{"alive" if self.monitor_t.is_alive() else "dead"}')

    def monitor_temperature(self):
        def _check_temperature():
            nodes = self.pods.get_nicknames()
            temperatures = self.pods.get_radio_temperatures(skip_logging=True, skip_exception=True, timeout=3,
                                                            retries=1)
            temp_log_catcher.add(nodes, temperatures)
            clients = self.clients.get_nicknames()
            client_temps = self.clients.get_temperature(skip_logging=True, skip_exception=True, timeout=3)
            temp_log_catcher.add(clients, client_temps)
            for node, node_temperatures in zip(nodes, temperatures):
                if type(node_temperatures) is not list:
                    continue
                for temp in node_temperatures:
                    if temp and temp > 82:
                        log.warning(f"{node.upper()} IS OVERHEATING!!! Current radios temperature: {node_temperatures}")
                        break
            for client, client_temp in zip(clients, client_temps):
                if type(client_temp) is int and client_temp > 82:
                    log.warning(f'CLIENT {client.upper()} IS OVERHEATING!!! Current temperature: {client_temp}')

        while True:
            try:
                _check_temperature()
            except Exception:
                # Try very hard to log the error, but keep going regardless what went wrong
                sep = "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                tb = traceback.format_exc()
                msg = sep.join(["", "Exception in temperature monitor thread:", tb, ""])
                try:
                    log.error(msg)
                except Exception:
                    try:
                        print(msg, file=sys.stderr, flush=True)
                    except Exception:
                        pass
            # Check temperature every minute, monitor queue the rest of the time
            try:
                cmd = self.monitor_main_q.get(block=True, timeout=60)
            except queue.Empty:
                pass
            else:
                if "STOP" in cmd:
                    log.info(f'Stopping temperature monitor thread: received {cmd} command')
                    break
                else:
                    log.warning(f"Unrecognised temperature monitor thread command: {cmd}")


class TempMonitorLogCatcher(LogCatcher):

    def add_screenshot(self, **_kwargs):
        pass

    def add(self, nodes, temperatures):
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%m-%d_%H:%M:%S") + " UTC"
        indent_str = f'\n{" ":2} - '
        msg_str = f"[{timestamp}] Nodes temperatures:"
        for node, temp in zip(nodes, temperatures):
            msg_str += f"{indent_str} {node}: {temp}"
        msg_str += '\n'
        self.add_to_logs(msg_str)


temp_log_catcher = TempMonitorLogCatcher(default_name='log_temperature_monitor')
