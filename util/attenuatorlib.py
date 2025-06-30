"""
Python library for controlling Mini-Circuits programmable attenuators from OSRT testbeds.

More information about the hardware devices supported can be found on the
`manufacturer webpage <https://www.minicircuits.com/softwaredownload/patt.html>`_.

Different attenuator device/devices can be configured in the location config file.
The `Attenuators` is a top-level location config key.
For a single channel devices, the key `channel:` should not be in the config file.

Example config:

.. code-block:: yaml

    Attenuators:
      - host: 10.3.3.103
        links: [gw, l1]   # indicate devices connected, use tab-completion in terminal
        name: att1
        password: ''
        port: 80
      - host: 172.21.30.105
        links: [gw, w1]
        name: att2
        password: ''
        port: 80
        channel: 1
      - host: 172.21.30.105
        links: [l1, w1]
        name: att3
        password: ''
        port: 80
        channel: 2


In the example above, a single-channel device is connected between ``gw`` and ``l1`` nodes. It's exposed under the name
``att1``. Then a single device with multiple channels is connected between ``gw`` and ``w1`` client, on channel 1,
and then ``l1`` and ``w1`` are connected on channel 2.

Note that the channel are indexed starting with a 1.

Commanline tool
---------------

Use the following commands to set or get attenuator level in terminal:

.. command-output:: osrt attenuator -h

.. command-output:: osrt attenuator get -h

.. command-output:: osrt attenuator set -h

"""

from lib_testbed.generic.util.config import TbConfig
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.client.client import ClientResolver

ATTENUATOR_URL = "http://{0}:{1}/{2}/"
ATTENUATOR_URL_PASSWORD = "http://{0}:{1}/{2};{3}/"


class AttenuatorObject:
    def __init__(self, attenuator_config, ssh_gateway_cfg):
        self.attenuator_config = attenuator_config
        self._ssh_gateway_cfg = ssh_gateway_cfg
        self.host, self.port, self.password, self.att_name = (
            self.attenuator_config["host"],
            self.attenuator_config["port"],
            self.attenuator_config["password"],
            self.attenuator_config["name"],
        )
        self.ssh_gateway = self.create_host_obj(self._ssh_gateway_cfg)

    @staticmethod
    def create_host_obj(ssh_gateway_cfg):
        dev_discovered = ClientResolver().get_device(**ssh_gateway_cfg)
        api_class = ClientResolver().resolve_client_api_class(dev_discovered)
        ssh_gateway_cfg.update({"dev": dev_discovered})
        ssh_gateway = api_class(**ssh_gateway_cfg)
        return ssh_gateway

    def execute_request(self, request: str, **kwargs) -> list[int, str, str]:
        """Execute request (str) against the attenuator and return a list with exit code, stdout and stderr streams."""
        url = (
            ATTENUATOR_URL.format(self.host, self.port, request)
            if not self.password
            else ATTENUATOR_URL_PASSWORD.format(self.host, self.port, self.password, request)
        )
        # intentionally not exposing passwords in the log:
        log.debug("Executing attenuation request: %s", ATTENUATOR_URL.format(self.host, self.port, request))
        output = self.ssh_gateway.run_raw(f"curl {url}", **kwargs)
        return output


class AttenuatorLib:
    def __init__(self, tb_config: TbConfig):
        self.config: TbConfig = tb_config
        # the atenuators object maps defined name into a tuple of attenuator object and links (list of 2 strings)
        self.attenuators: dict[str, tuple[AttenuatorObject, list[str]]] = {}
        self.init_config()

    def init_config(self) -> None:
        attenuators_config: list = self.config.get("Attenuators")
        if not attenuators_config:
            raise OpenSyncException(
                "Attenuator configuration not found.",
                "If an attenuator is present, configure it in the testbed configuration file",
            )
        attenuator_aliases = {}
        for attenuator in attenuators_config:
            name = attenuator["name"]
            attenuator_devices = attenuator["links"]
            ssh_gateway_cfg = self.get_ssh_gateway_cfg()
            attenuator_obj = AttenuatorObject(attenuator_config=attenuator, ssh_gateway_cfg=ssh_gateway_cfg)
            attenuator_aliases[name] = (attenuator_obj, attenuator_devices)
        self.attenuators = attenuator_aliases

    def get_ssh_gateway_cfg(self):
        ssh_gateway = self.config.get("ssh_gateway")
        if not ssh_gateway:
            raise IOError("SSH Gateway not found in testbed config")
        ssh_gateway_cfg = {"config": self.config, "device_type": "Clients", "nickname": "host", "type": "linux"}
        ssh_gateway_cfg["config"]["Clients"].append({"name": "host", "hostname": ssh_gateway, "type": "linux"})
        return ssh_gateway_cfg

    def get_attenuators_aliases(self) -> list[tuple[str, AttenuatorObject, str]]:
        """Get attenuators aliases. Returns a

        Returns: list() [att_name, att_obj, att_links]
        """
        attenuators_aliases = list()
        for attenuator_alias in self.attenuators:
            attenuator_obj, attenuator_links = self.attenuators[attenuator_alias]
            attenuators_aliases.append((attenuator_alias, attenuator_obj, attenuator_links))
        return attenuators_aliases

    def set_att(self, att_indicator: str | list[str], level: float | str, **kwargs) -> float:
        """
        Set attenuation 0-90dB (0.25dB step)

        Args:
            att_indicator: (list) List of attenuator links or (str) attenuator name
            level: (float|str) Attenuation level [dB]
            **kwargs:

        Returns:
        """
        if not isinstance(level, str):
            level = f"{level:.2f}"
        attenuator_obj = self.get_attenuator_obj(att_indicator)
        if attenuator_obj.attenuator_config.get("channel"):
            log.trace("Multichannel device - need to execute custom command")
            request = f"chan:{attenuator_obj.attenuator_config.get("channel")}:setatt:{level}"
        else:
            log.trace("Single channel device - using a single command.")
            request = f"setatt={level}"
        res = attenuator_obj.execute_request(request, **kwargs)

        if res[0]:
            # not successful command, raise a RuntimeError with both stdout & stderr streams
            raise RuntimeError(res[1] + "\n" + res[2])

        return self.get_att(att_indicator)

    def get_att(self, att_indicator, **kwargs) -> float:
        """Read attenuation from device.

        Args:
            att_indicator: (list) List of attenuator links or (str) attenuator name
            **kwargs:

        Returns: (float)
        """
        request = "att?"
        attenuator_obj = self.get_attenuator_obj(att_indicator)
        res = attenuator_obj.execute_request(request, **kwargs)
        if attenuator_obj.attenuator_config.get("channel"):
            log.trace("Multichannel device, response: %s", res[1])
            all_channels = res[1].split()
            return float(all_channels[attenuator_obj.attenuator_config.get("channel") - 1])
        log.trace("Single channel response to return: %s", res[1])
        return float(res[1])

    def get_attenuator_obj(self, att_indicator: str | list[str]) -> AttenuatorObject | None:
        """Get target attenuator object for given link (as list of string names of objects) or by name.

        Args:
            att_indicator: (list) Attenuator links or (str) attenuator name for matching the attenuator object

        Returns: (obj) Attenuator obj
        """
        att_aliases = self.get_attenuators_aliases()
        att_obj = None
        for att_alias in att_aliases:
            att_list_alias = att_alias[2]
            if set(att_indicator) == set(att_list_alias) or att_alias[0] == att_indicator:
                att_obj = att_alias[1]
                break
        if not att_obj:
            raise Exception(
                f"Attenuator not found for {att_indicator} attenuator list. "
                f"Available attenuators:\n{self.attenuators}"
            )
        return att_obj
