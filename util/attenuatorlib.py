from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.client.client import ClientResolver

ATTENUATOR_URL = "http://{0}:{1}/{2}/"
ATTENUATOR_URL_PASSWORD = "http://{0}:{1}/{2};{3}/"


class AttenuatorLib:
    def __init__(self, test_case=True, **kwargs):
        self.config = kwargs.get("config")
        self.attenuators = self.init_config(test_case)

    def init_config(self, test_case):
        attenuators_config = self.config.get("Attenuators")
        if not attenuators_config:
            raise OpenSyncException(
                "Attenuator configuration not found.",
                "If an attenuator is present, configure it in the testbed configuration file",
            )
        attenuator_aliases = {}
        for attenuator in attenuators_config:
            name = attenuator["name"]
            attenuator_devices = attenuator["links"]
            ssh_gateway_cfg = self.get_ssh_gateway_cfg(attenuator)
            attenuator_obj = AttenuatorObject(
                ssh_gateway_cfg, attenuator["host"], attenuator["port"], attenuator["password"], test_case, name
            )
            attenuator_aliases[name] = (attenuator_obj, attenuator_devices)
        return attenuator_aliases

    def get_ssh_gateway_cfg(self, attenuator_cfg):
        ssh_gateway = (
            attenuator_cfg.get("ssh_gateway") if attenuator_cfg.get("ssh_gateway") else self.config.get("ssh_gateway")
        )
        if not ssh_gateway:
            raise Exception("SSH Gateway not found in testbed config")
        ssh_gateway_cfg = {"config": self.config, "device_type": "Clients", "nickname": "host", "type": "linux"}
        ssh_gateway_cfg["config"]["Clients"].append({"name": "host", "hostname": ssh_gateway, "type": "linux"})
        return ssh_gateway_cfg

    def get_attenuators_aliases(self):
        """
        Get attenuators aliases

        Returns: list() [att_name, att_obj, att_links]

        """
        attenuators_aliases = list()
        for attenuator_alias in self.attenuators:
            attenuator_obj, attenuator_links = self.attenuators[attenuator_alias]
            attenuators_aliases.append((attenuator_alias, attenuator_obj, attenuator_links))
        return attenuators_aliases

    def set_att(self, attenuation, att_indicator, **kwargs):
        """
        Set attenuation 0-90dB (0.25dB step)

        Args:
            attenuation: (float) Attenuation [dB]
            att_indicator: (list) List of attenuator links or (str) attenuator name
            **kwargs:

        Returns: (float)

        """
        request = f"SETATT={attenuation}"
        attenuator_obj = self.get_attenuator_obj(att_indicator)
        return attenuator_obj.execute_request(request, **kwargs)

    def read_att(self, att_indicator, **kwargs):
        """
        Read attenuation

        Args:
            att_indicator: (list) List of attenuator links or (str) attenuator name
            **kwargs:

        Returns: (float)

        """
        request = "ATT?"
        attenuator_obj = self.get_attenuator_obj(att_indicator)
        return attenuator_obj.execute_request(request, **kwargs)

    def get_config(self):
        """
        Get attenuation config

        Returns: (json) attenuation configuration
        """
        return self.config["Attenuators"]

    def get_list(self):
        """
        Get list of attenuation names

        Returns: attenuation list names
        """
        att_names = [att_alias[0] for att_alias in self.get_attenuators_aliases()]
        return att_names

    def get_attenuator_obj(self, att_indicator):
        """
        Get target attenuator object

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


class AttenuatorObject:
    def __init__(self, ssh_gateway_cfg, host, port, password, test_case, name):
        self.host, self.port, self.password, self.test_case, self.att_name = host, port, password, test_case, name
        self.ssh_gateway = self.create_host_obj(ssh_gateway_cfg)

    @staticmethod
    def create_host_obj(ssh_gateway_cfg):
        dev_discovered = ClientResolver().get_device(**ssh_gateway_cfg)
        api_class = ClientResolver().resolve_client_api_class(dev_discovered)
        ssh_gateway_cfg.update({"dev": dev_discovered})
        ssh_gateway = api_class(**ssh_gateway_cfg)
        return ssh_gateway

    def execute_request(self, request, **kwargs):
        url = (
            ATTENUATOR_URL.format(self.host, self.port, request)
            if not self.password
            else ATTENUATOR_URL.format(self.host, self.port, self.password, request)
        )
        output = (
            self.ssh_gateway.run(f"curl {url}", **kwargs)
            if self.test_case
            else self.ssh_gateway.run_raw(f"curl {url}", **kwargs)
        )
        output = self.create_output(output)
        return output

    def create_output(self, output):
        if not self.test_case:
            output.insert(0, self.att_name)
            # Clear stderr output if ret value 0 for tools
            if output[1] == 0:
                output[3] = ""
            output = [output]
        else:
            output = float(output)
        return output
