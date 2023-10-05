from lib_testbed.generic.rpower.pdu_units.common_pdu_lib import CommonPduLib
from lib_testbed.generic.rpower import rpower_local_lib


class NoRpowerOnRpiServerLib(CommonPduLib):
    def __init__(
        self, server_object, rpower_devices, pod_names, client_names, address, user, password, port, tb_config, **kwargs
    ):
        super().__init__(
            server_object, rpower_devices, pod_names, client_names, address, user, password, port, tb_config, **kwargs
        )
        rpower_local_lib.rpower_init_config(tb_config)

    def on(self, device_names):
        self.set_request_timestamp(device_names)
        return rpower_local_lib.rpower_on(self.get_devices_to_execute(device_names))

    def off(self, device_names):
        self.set_request_timestamp(device_names)
        return rpower_local_lib.rpower_off(self.get_devices_to_execute(device_names))

    def cycle(self, device_names, timeout=5):
        return rpower_local_lib.rpower_cycle(self.get_devices_to_execute(device_names), timeout=timeout)

    def status(self, device_names):
        return rpower_local_lib.rpower_status(self.get_devices_to_execute(device_names))

    @staticmethod
    def model():
        return rpower_local_lib.rpower_model()

    @staticmethod
    def version():
        return rpower_local_lib.rpower_version()

    @staticmethod
    def get_name():
        return "no_rpower_on_rpi_server"
