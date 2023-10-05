"""Dedicated library for "lib_testbed/generic/tools/rpower" tool purposes"""
from lib_testbed.generic.rpower.rpowerlib import PowerControllerLib


class PowerControllerTool(PowerControllerLib):
    def __init__(self, conf, device_names: str | list = None, **kwargs):
        super().__init__(conf, **kwargs)
        self.device_names = device_names

    def on(self):
        "Turn devices on"
        return super().on(device_names=self.device_names)

    def off(self):
        "Turn devices off"
        return super().off(device_names=self.device_names)

    def cycle(self, timeout: int = 5) -> dict:
        "Power cycle devices"
        return super().cycle(device_names=self.device_names, timeout=timeout)

    def status(self):
        "Get devices power status"
        return super().status(device_names=self.device_names)
