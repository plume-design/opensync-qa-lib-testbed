import os
import inspect
import threading
from lib_testbed.generic.util.allure_util import AllureUtil
from lib_testbed.generic.util.common import Results
from lib_testbed.generic.util.ssh.sshexception import SshException
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.request_handler import parse_request

DEVICE_TIMEOUT = 60 * 60


class DeviceApi:
    def __init__(self, **kwargs):
        self.start_class_handler = True
        self.lib = None

    def get_device_dir(self):
        return inspect.getfile(self.__class__)

    def is_mgmt_access(self):
        return True if self.lib.device else False

    def run(self, cmd, skip_exception=False, strip=True, **kwargs):
        results = self.lib.run_command(cmd, **kwargs)
        if strip:
            results = self.lib.strip_stdout_result(results)
        return self.lib.get_stdout(results, skip_exception)

    def run_raw(self, cmd, strip=True, **kwargs):
        """Run a command on a single device
        :return: [ret_value, stdout, stderr]"""
        results = self.lib.run_command(cmd, **kwargs)
        if strip:
            results = self.lib.strip_stdout_result(results)
        return results
        # if self.lib.multi_devices:
        #     return results
        # else:
        #     return results[0]

    @parse_request
    def teardown_class_handler(self, request):
        self.start_class_handler = True
        self.lib.free_device()

    @parse_request
    def setup_method_handler(self, request):
        def get_location_name(config):
            return os.path.basename(config.get("location_file", "")).split(".")[0]

        if not request:
            return
        AllureUtil(request.config).add_environment(
            "config", get_location_name(self.lib.config), request.node.originalname
        )

    def get_name(self):
        """
        Method for return only one device name
        Returns: (str)

        """
        return self.lib.get_name()

    def get_nickname(self):
        """
        Method for return only one device name
        Returns: (str)

        """
        return self.lib.get_nickname()

    def get_serial_by_name(self, device_type, device_name):
        """
        Method for return serial based on device name
        Args:
            device_type: (str) Nodes/Clients
            device_name: (str) Name of the device

        Returns: (str) Device ID

        """
        return self.lib.device.config.get("id")

    def wait_available(self, timeout=120, **kwargs):
        response = self.lib.wait_available(timeout=timeout)
        return self.lib.get_stdout(response, **kwargs)

    def wait_unavailable(self, timeout=120, **kwargs):
        response = self.lib.wait_unavailable(timeout=timeout)
        return self.lib.get_stdout(response, **kwargs)


class DevicesApi:
    def __init__(self, obj_list, **kwargs):
        if not obj_list:
            log.warning("No Device available")
        self.obj_list = obj_list
        self.lib = DevicesApi.DevicesLib(self.obj_list)
        self.ovsdb = DevicesApi.DevicesApiOvsdb(self.obj_list, self)
        self.iface = DevicesApi.DevicesApiIface(self.obj_list, self)
        self.msg = DevicesApi.DevicesApiMsg(self.obj_list, self)
        self.use_devices = DevicesApi.UseDevices

    @staticmethod
    def is_device_no_management(device_type):
        if device_type == "Clients":
            prefix = "CLIENTS"
        elif device_type == "Nodes":
            prefix = "PODS"
        else:
            raise Exception(f"Unexpected device type: {device_type}")
        if os.environ.get(f"{prefix}_NO_MGMT") == "true":
            return True
        return False

    def __getattr__(self, attr_name):
        return DevicesApi.getattr(self, attr_name)

    @classmethod
    def getattr(cls, self_obj, attr_name):
        def is_ssh_exception(results):
            if isinstance(results, SshException):
                return True
            if isinstance(results, list):
                for result in results:
                    if isinstance(result, SshException):
                        return True
            return False

        def raise_multi_ssh_exception(results):
            exception = {}
            names = []
            messages = []
            cmds = []
            rets = []
            stdouts = []
            stderrs = []

            for result in results:
                if not isinstance(result, SshException):
                    continue
                ssh_exception = result
                names.append(ssh_exception.name)
                messages.append(ssh_exception.message)
                cmds.append(ssh_exception.cmd)
                rets.append(ssh_exception.ret)
                stdouts.append(ssh_exception.stdout)
                stderrs.append(ssh_exception.stderr)
            exception["name"] = names
            exception["message"] = messages
            exception["cmd"] = cmds
            exception["ret"] = rets
            exception["stdout"] = stdouts
            exception["stderr"] = stderrs
            raise SshException(**exception)

        def hooked(*args, **kwargs):
            jobs = []
            results_dict = {}
            not_callable = kwargs.pop("not_callable", None)
            skip_exception = True if kwargs.get("skip_exception") else False
            for obj in self_obj.obj_list:
                attr = obj.__getattribute__(attr_name)
                # for debug purposes only
                call_debug = False
                if call_debug:
                    attr(*args, **kwargs)
                thread = threading.Thread(
                    target=Results.call_method,
                    args=(
                        attr,
                        self_obj,
                        not_callable,
                        obj,
                        results_dict,
                        *args,
                    ),
                    kwargs=kwargs,
                    daemon=True,
                )
                thread.start()
                jobs.append(thread)

            for job in jobs:
                # In case of ssh do not set timeout for connection
                timeout = None if attr_name == "ssh" else DEVICE_TIMEOUT
                job.join(timeout=timeout)

            results = Results.get_sorted_results(results_dict, self_obj.obj_list, skip_exception)
            if is_ssh_exception(results):
                raise_multi_ssh_exception(results)
            return results

        if not self_obj.obj_list:
            raise Exception("Devices not available")
        attr = self_obj.obj_list[0].__getattribute__(attr_name)
        if callable(attr):
            return hooked
        else:
            return hooked(not_callable=True)

    def get_devices(self):
        devices = []
        for obj in self.obj_list:
            devices.append(obj)
        return devices

    def get_nicknames(self):
        devices = self.get_devices()
        return [device.get_nickname() for device in devices]

    # TODO: Create PodDevicesApi class
    def poll_pods_sanity(self, timeout=500):
        devices = self.get_devices()
        sanities = [device.poll_pod_sanity(timeout=timeout) for device in devices]
        for sanity in sanities:
            if not isinstance(sanity, int):
                raise sanity
        return any(sanities)

    class UseDevices:
        def __init__(self, api_obj_list):
            self.obj_list = api_obj_list

        def __getattr__(self, attr_name):
            return DevicesApi.getattr(self, attr_name)

        def get_devices(self):
            devices = []
            for obj in self.obj_list:
                devices.append(obj)
            return devices

        def get_nicknames(self):
            devices = self.get_devices()
            return [device.get_nickname() for device in devices]

        # TODO: Create PodUseDevices class
        def poll_pods_sanity(self, timeout=500):
            devices = self.get_devices()
            sanities = [device.poll_pod_sanity(timeout=timeout) for device in devices]
            for sanity in sanities:
                if not isinstance(sanity, int):
                    raise sanity
            return any(sanities)

    class DevicesLib:
        def __init__(self, api_obj_list):
            if not api_obj_list:
                self.obj_list = []
            else:
                self.obj_list = [api_obj.lib for api_obj in api_obj_list]
            self.tool = DevicesApi.DevicesLib.DevicesTool(self.obj_list)
            self.log_catcher = DevicesApi.DevicesLib.DevicesLogCatcher(self.obj_list)
            self.ovsdb = DevicesApi.DevicesLib.DevicesOvsdb(self.obj_list, self)
            self.iface = DevicesApi.DevicesLib.DevicesIface(self.obj_list, self)
            self.msg = DevicesApi.DevicesLib.DevicesMsg(self.obj_list, self)

        def get_nicknames(self):
            names = []
            for obj in self.obj_list:
                names.append(obj.get_nickname())
            return names

        def __getattr__(self, attr_name):
            return DevicesApi.getattr(self, attr_name)

        class DevicesTool:
            def __init__(self, lib_obj_list):
                if not lib_obj_list:
                    self.obj_list = []
                else:
                    self.obj_list = [lib_obj.tool for lib_obj in lib_obj_list]

            def __getattr__(self, attr_name):
                return DevicesApi.getattr(self, attr_name)

        class DevicesLogCatcher:
            def __init__(self, lib_obj_list):
                if not lib_obj_list:
                    self.obj_list = []
                else:
                    self.obj_list = [lib_obj.log_catcher for lib_obj in lib_obj_list]

            def __getattr__(self, attr_name):
                return DevicesApi.getattr(self, attr_name)

        class DevicesOvsdb:
            def __init__(self, lib_obj_list, pod_lib):
                if not lib_obj_list:
                    self.obj_list = []
                else:
                    self.obj_list = [lib_obj.ovsdb for lib_obj in lib_obj_list if hasattr(lib_obj, "ovsdb")]
                if self.obj_list:
                    self.lib = pod_lib

            def __getattr__(self, attr_name):
                return DevicesApi.getattr(self, attr_name)

        class DevicesIface:
            def __init__(self, lib_obj_list, pod_lib):
                if not lib_obj_list:
                    self.obj_list = []
                else:
                    self.obj_list = [lib_obj.iface for lib_obj in lib_obj_list if hasattr(lib_obj, "iface")]
                if self.obj_list:
                    self.lib = pod_lib

            def __getattr__(self, attr_name):
                return DevicesApi.getattr(self, attr_name)

        class DevicesMsg:
            def __init__(self, lib_obj_list, pod_lib):
                if not lib_obj_list:
                    self.obj_list = []
                else:
                    self.obj_list = [lib_obj.msg for lib_obj in lib_obj_list if hasattr(lib_obj, "msg")]
                if self.obj_list:
                    self.lib = pod_lib

            def __getattr__(self, attr_name):
                return DevicesApi.getattr(self, attr_name)

        class DevicesCloud:
            def __init__(self, lib_obj_list):
                if not lib_obj_list:
                    self.obj_list = []
                else:
                    self.obj_list = [lib_obj.cloud for lib_obj in lib_obj_list]

            def __getattr__(self, attr_name):
                # return DevicesApi.getattr(self, attr_name)
                raise KeyError("Pods doesn't support cloud object yet")

    class DevicesApiOvsdb:
        def __init__(self, api_obj_list, api):
            if not api_obj_list:
                self.obj_list = []
            else:
                self.obj_list = [api_obj.ovsdb for api_obj in api_obj_list if hasattr(api_obj, "ovsdb")]
            if self.obj_list:
                self.pod_api = api

        def __getattr__(self, attr_name):
            return DevicesApi.getattr(self, attr_name)

    class DevicesApiIface:
        def __init__(self, api_obj_list, api):
            if not api_obj_list:
                self.obj_list = []
            else:
                self.obj_list = [api_obj.iface for api_obj in api_obj_list if hasattr(api_obj, "iface")]
            if self.obj_list:
                self.pod_api = api

        def __getattr__(self, attr_name):
            return DevicesApi.getattr(self, attr_name)

    class DevicesApiMsg:
        def __init__(self, api_obj_list, api):
            if not api_obj_list:
                self.obj_list = []
            else:
                self.obj_list = [api_obj.msg for api_obj in api_obj_list if hasattr(api_obj, "msg")]
            if self.obj_list:
                self.pod_api = api

        def __getattr__(self, attr_name):
            return DevicesApi.getattr(self, attr_name)
