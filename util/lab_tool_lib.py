import sys
import traceback
import concurrent.futures

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util import config
from lib_testbed.generic.util.reservelib import PyReservePlugin
from lib_testbed.generic.client.client import Clients
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.pod.pod import Pods


class LabToolLib:
    """
    Library for managing all testbeds in laboratory
    """
    def __init__(self, **kwargs):
        self.tb_configs = self._load_test_bed_configs(kwargs.get('config'))
        self.json_output = kwargs.get('json')

    @staticmethod
    def _load_test_bed_configs(lab_config):
        lab_configs = {}
        for tb_name in lab_config.split('\n'):
            if not tb_name:
                continue
            try:
                lab_configs[tb_name] = config.load_tb_config(tb_name, skip_deployment=True, skip_capabilities=True)
            except OpenSyncException as e:
                log.error(f"Cannot load {tb_name}:\n{e}")

        return lab_configs

    def upgrade_clients(self, version='latest'):
        """
        Update FW for client devices in the testbed

        Select 'latest' or 'stable' version. Testbed server will be also upgraded.
        """
        assert version in ['latest', 'stable']
        testbed_states = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_upgrade_client = {executor.submit(self._single_test_bed_clients_upgrade, tb_name, version): tb_name
                                     for tb_name in self.tb_configs}
            for future in concurrent.futures.as_completed(future_upgrade_client, timeout=4 * 60 * 60):
                tb_name = future_upgrade_client[future]
                ret = future.result()
                testbed_states[tb_name] = ret

        return {'Upgrade clients': testbed_states}

    def versions(self):
        """
        Check FW for client devices in the testbed

        Select 'latest' or 'stable' version.
        """
        testbed_states = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_version = {executor.submit(self._single_test_bed_versions, tb_name): tb_name
                              for tb_name in self.tb_configs}
            for future in concurrent.futures.as_completed(future_version, timeout=4 * 60 * 60):
                tb_name = future_version[future]
                ret = future.result()
                testbed_states[tb_name] = ret

        return {'Versions': testbed_states}

    def fuse_status(self):
        testbed_states = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_status = {executor.submit(self._single_test_bed_fuse_status, tb_name): tb_name
                             for tb_name in self.tb_configs}
            for future in concurrent.futures.as_completed(future_status, timeout=4 * 60 * 60):
                tb_name = future_status[future]
                ret = future.result()
                testbed_states[tb_name] = ret

        return {'Fuse status': testbed_states}

    def _single_test_bed_versions(self, tb_name):
        tb_config = config.load_tb_config(tb_name, skip_deployment=True, skip_capabilities=True)
        server_lib = self._get_client_lib(tb_config, 'server')
        ret = server_lib.version()[0]
        out_code = ret[0]
        std_out = ''
        std_err = ''
        if ret[1]:
            std_out = f"TB server:\n{ret[1]}"
        if ret[2]:
            std_err = f"TB server:\n{ret[2]}"

        client_lib = self._get_client_lib(tb_config, 'clients')
        ret = client_lib.version()
        for nickname, ret_client in zip(client_lib.get_nicknames(), ret):
            if ret_client[0] and ret_client[0] != 3:
                log.error(f"[{tb_name}] Upgrading {nickname} client failed: {ret_client[1]}\n{ret_client[2]}")
                out_code = 1
            if ret_client[1]:
                std_out += f"\n\n{nickname}:\n{ret_client[1]}"
            if ret_client[2]:
                std_err += f"\n\n{nickname}:\n{ret_client[2]}"

        return [out_code, std_out, std_err]

    def _single_test_bed_clients_upgrade(self, tb_name, version):
        tb_config = config.load_tb_config(tb_name, skip_deployment=True)
        reserve_tb = PyReservePlugin(tb_name, tb_pool_name=None, skip_reservation=False, tb_config=tb_config)
        try:
            reserve_tb.reserve_testbed()
        except AssertionError:
            return [2, '', f"{tb_name} still reserved"]

        # first we need to upgrade testbed server
        log.warning(f"[{tb_name}] Upgrading server")
        server_lib = self._get_client_lib(tb_config, 'server')
        # before server upgrade we need extend the reservation as server will be rebooting and someone can still it
        reserve_tb.res.reserve_test_bed(60)
        try:
            ret = server_lib.upgrade(version=version)[0]
        except Exception as e:
            log.error(f"[{tb_name}] Server upgrade error:\n{e}")
            return [4, '', f"Server upgrade error:\n{e}"]
        # restore similar reservation timeout (to be sure it's not manual)
        reserve_tb.res.reserve_test_bed(9)
        if ret[0] and ret[0] != 3:
            log.error(f"[{tb_name}] Upgrading server failed: {ret[1]}\n{ret[2]}")
            reserve_tb.un_reserve_testbed()
            return ret
        ret_ie_check = server_lib.ping_check(count=2, fqdn_check=False)[0]
        if ret_ie_check[0]:
            log.error(f"[{tb_name}] Server lost internet access: {ret[1]}\n{ret[2]}")
            reserve_tb.un_reserve_testbed()
            return ret_ie_check

        std_out = ''
        std_err = ''
        if ret[1]:
            std_out = f"TB server:\n{ret[1]}"
        if ret[2]:
            std_err = f"TB server:\n{ret[2]}"

        # upgrade clients
        client_lib = self._get_client_lib(tb_config, 'clients')
        log.warning(f"[{tb_name}] Upgrading clients")
        try:
            ret = client_lib.upgrade(version=version)
        except Exception as e:
            log.error(f"[{tb_name}] Clients upgrade error:\n{e}")
            return [4, std_out, f"{std_err}\n\nClients upgrade error:\n{e}"]
        err_code = 0
        for nickname, ret_client in zip(client_lib.get_nicknames(), ret):
            if ret_client[0] and ret_client[0] != 3:
                log.error(f"[{tb_name}] Upgrading {nickname} client failed: {ret_client[1]}\n{ret_client[2]}")
                err_code = 1
            if ret_client[1]:
                std_out += f"\n\n{nickname}:\n{ret_client[1]}"
            if ret_client[2]:
                std_err += f"\n\n{nickname}:\n{ret_client[2]}"
        reserve_tb.un_reserve_testbed()
        log.warning(f"[{tb_name}] Upgrade finished for all clients")
        return [err_code, std_out, std_err]

    def _single_test_bed_fuse_status(self, tb_name):
        tb_config = config.load_tb_config(tb_name, skip_deployment=True)
        pod_lib = self._get_pod_lib(tb_config)
        ret_fuse = pod_lib.is_fw_fuse_burned(skip_exception=True)
        ret_ping = pod_lib.ping()
        std_out_fuse = ''
        serials = [node['id'] for node in tb_config['Nodes']]
        for serial, nickname, ret_pod, ret_ping in zip(serials, pod_lib.get_nicknames(), ret_fuse, ret_ping):
            if ret_ping[0]:
                std_out_fuse += f"{serial}({nickname}): ERROR\n"
            else:
                std_out_fuse += f"{serial}({nickname}): {'Fused' if ret_pod else 'Unfused'}\n"
        return [std_out_fuse]

    @staticmethod
    def _get_client_lib(tb_config, cl_type):
        """
        Get client object
        """
        if cl_type == 'server':
            kwargs = {'config': tb_config, 'multi_obj': True, 'type': 'rpi', 'nicknames': ['host']}
        elif cl_type == 'clients':
            kwargs = {'config': tb_config, 'multi_obj': True, 'type': 'linux|rpi|hydra'}
        else:
            raise Exception("Unsupported client type, Use 'host' or 'clients'")
        try:
            clients_obj = Clients(**kwargs)
            clients_api = clients_obj.resolve_obj(**kwargs)
            client_lib = clients_api.lib
            return client_lib
        except Exception:
            traceback.print_exc(limit=2, file=sys.stdout)
            raise

    @staticmethod
    def _get_pod_lib(tb_config):
        kwargs = {'config': tb_config, 'multi_obj': True}
        try:
            pods_obj = Pods(**kwargs)
            pods_api = pods_obj.resolve_obj(**kwargs)
            return pods_api.lib
        except Exception:
            traceback.print_exc(limit=2, file=sys.stdout)
            raise
