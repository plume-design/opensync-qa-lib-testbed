#!/usr/bin/env python3
import logging
from lib_testbed.generic.util.logger import log, LOGGER_NAME, update_logger_with_stream_handler  # noqa: E402
from lib_testbed.generic.pod.pod import Pod  # noqa: E402

GW_NAME = "gw"


class PodExt:
    def __init__(self, ssh_gateway, gw_id, model, host, host_recover, capabilities, name=GW_NAME):
        config = self.create_config(
            ssh_gateway=ssh_gateway,
            gw_id=gw_id,
            model=model,
            host=host,
            host_recover=host_recover,
            capabilities=capabilities,
            name=name,
        )
        self.config = config
        # self.recover()

    def recover(self):
        update_logger_with_stream_handler(log)
        pod_api = self.get_pod_api()
        self.set_log_level(logging.DEBUG)
        return pod_api.lib.recover()

    def get_pod_api(self):
        kwargs = {"config": self.config, "multi_obj": False, "nickname": self.config.get("name")}
        pod_obj = Pod(**kwargs)
        pod_api = pod_obj.resolve_obj(**kwargs)
        return pod_api

    @staticmethod
    def set_log_level(level):
        # Set logging level
        logger = logging.getLogger(LOGGER_NAME)
        logger.setLevel(level)

    @staticmethod
    def create_config(ssh_gateway, gw_id, model, host, host_recover, capabilities, name=GW_NAME):
        config = {
            "ssh_gateway": ssh_gateway,
            "Nodes": [
                {
                    "name": name,
                    "id": gw_id,
                    "model": model,
                    "host": host,
                    "host_recover": host_recover,
                    "capabilities": capabilities,
                }
            ],
        }
        return config
