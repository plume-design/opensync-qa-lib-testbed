#!/usr/bin/env python3
import re
import os
import sys
import json
import time
import zlib
import base64
import random
import socket
import ipaddress
import unicodedata
import paho.mqtt.client as paho_client  # paho-mqtt==1.3.0
from multiprocessing import Lock
from google.protobuf.json_format import MessageToJson
from google.protobuf.json_format import Parse
from google.protobuf.message import EncodeError, DecodeError

from lib_testbed.generic.mqtt.proto_util import ProtoUtil
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.logger import LogCatcher
from lib_testbed.generic.util.common import JsonPrettyPrinter
from lib_testbed.generic.util.common import BASE_DIR
from lib_testbed.generic.util.request_handler import parse_request


class MqttClient:
    def __init__(self, config, **_kwargs):
        self.config = config
        self.clients = []
        self.report_proto = None
        self.proto_util = ProtoUtil()
        self.resolver = MqttResolver()
        self.log_catcher = MqttLogCatcher(default_name="log_mqtt", obj=self)
        self.fake_stats = MqttFakeStats(self.publish)
        self.mqtt_processing = MqttProcessing(mqtt_lib=self)
        self.messages = []
        self.lock = Lock()
        self.max_messages = None
        self.terminate = False
        self.show_log = True
        self.clean_on_setup_method = config.get("clean_mqtt_on_setup_method", True)

    def connect(self, hosts, topic, on_message_cb=None, certs=None):
        with self.lock:
            self.terminate = False
        self.clean_messages(show_log=False)
        self.max_messages = None
        current_hosts = self.get_all_hosts()
        port = self.config.get("mqtt_port", 1883)
        log.info(f"Mqtt connecting to hosts: {hosts}, port: {port}")
        log.info(f"topic: {topic}", indent=1)
        for host in hosts:
            if host in current_hosts:
                raise Exception(f"Host: {host} already in use")
            ssl = True if port != 1883 else False
            client = self.paco_client(ssl=ssl, certs=certs)
            try:
                client.connect(host, port)
            except ConnectionRefusedError:
                log.error(f"Connection refused with {host}. Broker is down. Please contact net-ops team.")
                continue
            client.subscribe(topic)
            client.on_message_cb = on_message_cb
            client.loop_start()
            self.clients.append(client)
        assert self.clients, f"Can not connect to any of mqtt brokers: {hosts}"

    def wait_messages(self, timeout, skip_exception=False, close=True, pivot=None, new_messages_count=None):
        """
        Wait for mqtt messages. Either till self.max_messages or new_messages_count
        Args:
            timeout: (int) time to wait for new messages
            skip_exception: (bool) do not raise an exception if no new mqtt was received
            close: (bool) close connection once required messages arrive
            pivot: (int) messages starting index to return
            new_messages_count: (int) number of new messages to wait for

        Returns: (list) mqtt messages

        """
        if not self.clients:
            raise Exception("No client connected")
        if pivot is None:
            pivot = 0 if not new_messages_count else len(self.messages)
        max_messages = new_messages_count if new_messages_count else self.max_messages
        max_messages_str = f"{max_messages} " if max_messages else ""
        log.info(f"Waiting for {max_messages_str}mqtt messages, timeout: {timeout} sec")
        timeout_err = False
        start_time = time.time()
        while time.time() - start_time < timeout:
            with self.lock:
                if self.terminate or max_messages and len(self.messages[pivot:]) >= max_messages:
                    self.terminate = close
                    break
            time.sleep(0.1)  # Delay next poll
        else:
            timeout_err = True
        if close:
            self.close()
        if not skip_exception and timeout_err:
            raise TimeoutError(f"Mqtt collection is not terminated within timeout: {timeout}s")
        return self.get_messages()[pivot:]

    def get_pivot(self):
        return len(self.messages)

    def collect(self, topic, on_message_cb, timeout, wait=True, max_messages=None, **kwargs):
        # set suitable proto-decoder for topic
        self.report_proto = self.proto_util.get_proto_decoder(topic)
        hosts = MqttResolver.get_hosts(self.config)
        if not hosts:
            raise Exception(f"No found any mqtt hosts for the following topic: {topic} from zookeeper")
        self.connect(hosts, topic, on_message_cb)
        self.max_messages = max_messages
        if not wait:
            return []
        return self.wait_messages(timeout, **kwargs)

    def collect_statistics(
        self, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None, topic=None, **kwargs
    ):
        if not topic:
            topic = MqttResolver.get_statistic_topic(self.config, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages, **kwargs)

    def collect_dns_queries(self, device_id, on_message_cb, timeout=5 * 60, wait=True, max_messages=1):
        topic = MqttResolver.get_dns_queries_topic(self.config, device_id)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_sni_requests(self, device_id, on_message_cb, timeout=5 * 60, wait=True, max_messages=1):
        topic = MqttResolver.get_sni_requests_topic(self.config, device_id)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_ip_threats(self, device_id, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_ip_threats_topic(self.config, device_id)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_wc_stats(self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_wc_stats_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_hero_stats(self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_hero_stats_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_fcm_flows(
        self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None, topic=None
    ):
        topic = MqttResolver.get_fcm_flows_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_fcm_lan_stats(
        self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None, topic=None
    ):
        if not topic:
            topic = MqttResolver.get_fcm_lan_stats_topic(self.config, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_mdns_records(self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_mdns_records_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_adt_report(self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_adt_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_interface_stats_records(
        self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None
    ):
        topic = MqttResolver.get_interface_stats_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_time_events_records(self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_time_events_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_wifi_blaster_stats(self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_wifi_blaster_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    def collect_dpi_stats(self, device_id, lid, on_message_cb, timeout=5 * 60, wait=True, max_messages=None):
        topic = MqttResolver.get_dpi_stats_topic(self.config, device_id, lid)
        return self.collect(topic, on_message_cb, timeout, wait, max_messages)

    # The callback for when the client receives a CONNACK response from the server.
    @staticmethod
    def on_connect(client, obj, flags, result):
        assert not result, f"Mqtt failed to connect. Error result code: {result}"

    # The callback when message is received from the server.
    def on_message(self, client, obj, msg):
        with self.lock:
            if self.terminate:
                # Skip message after termination flag is set
                return
            # Try to unzip
            try:
                message = zlib.decompress(msg.payload)
            except zlib.error:
                message = msg.payload

            # try to parse google protobuf (statistic case)
            try:
                self.report_proto.ParseFromString(message)
                message = MessageToJson(self.report_proto)
            except DecodeError:
                pass
            terminate = False
            message = self.mqtt_processing.post_run(raw_msg=message)
            message = json.loads(message)
            self.log_catcher.add(message)
            org_message = message.copy()
            if hasattr(client, "on_message_cb") and client.on_message_cb:
                try:
                    resp = client.on_message_cb(self, message)
                    if not isinstance(resp, tuple) or len(resp) != 2:
                        log.error("Unexpected on_message_cb returned value. Expecting tuple (msg, terminate)")
                        message = None
                        terminate = False
                    else:
                        message, terminate = resp
                except Exception:
                    log.exception("Failed to call on_message_cb")
                self.terminate |= terminate
                if self.terminate:
                    log.info(f"Terminate mqtt message collection for {client._host}")

            self.log_message(org_message, message)
            if message:
                self.add_message(message)

    def on_publish(self, client, userdata, result):
        pass

    def log_message(self, message, new_message):
        def get_node_id_from_the_message():
            # general case
            node_id = tmp_message.get("nodeID") or tmp_message.get("nodeId")
            if node_id:
                return node_id
            # FCM case
            node_id = tmp_message.get("observationPoint", {}).get("nodeId")
            if node_id:
                return node_id
            # dumb fallback
            return list(tmp_message.keys())[0]

        if new_message:
            tmp_message = new_message
        else:
            tmp_message = message
        node_id = get_node_id_from_the_message()
        if not new_message:
            log.info(f"Skip message for: {node_id}")
        else:
            number_of_messages = len(self.get_messages()) + 1
            max_messages_info = f"/{self.max_messages}" if self.max_messages else ""
            if self.show_log:
                log.info(f"Received message: {number_of_messages}{max_messages_info} for: {node_id}")

    @parse_request
    def setup_method_handler(self, request):
        if self.clean_on_setup_method:
            self.clean_messages(show_log=False)

    @parse_request
    def teardown_class_handler(self, request):
        self.close()

    @staticmethod
    def get_name():
        return "mqtt_client"

    def set_config(self, config):
        self.config = config

    def get_all_hosts(self):
        return [client._host for client in self.clients]

    def get_client_by_host(self, host):
        hosts = self.get_all_hosts()
        if not hosts or host not in hosts:
            return None
        return self.clients[hosts.index(host)]

    def paco_client(self, ssl=False, certs=None):
        if certs is None:
            certs = {}
        client = paho_client.Client()
        client.on_message = self.on_message
        client.on_connect = self.on_connect
        client.on_publish = self.on_publish
        if ssl:
            log.info("Using TLS in mqtt connection")
            ext_cert_path = os.path.join(BASE_DIR, "lib_testbed", "generic", "mqtt", "certs", "ext")
            cert_dir = (
                ext_cert_path
                if os.path.exists(ext_cert_path)
                else os.path.join(BASE_DIR, "lib_testbed", "generic", "mqtt", "certs")
            )

            ca_cert = certs.get("ca_cert", os.path.join(cert_dir, "ca-rpi.pem"))
            cert_file = certs.get("cert_file", os.path.join(cert_dir, "client.pem"))
            key_file = certs.get("key_file", os.path.join(cert_dir, "client_dec.key"))

            cert_file = cert_file if os.path.exists(cert_file) else None
            key_file = key_file if os.path.exists(key_file) else None

            log.info(f"Setting certs ca_cert={ca_cert}, cert_file={cert_file}, key_file={key_file}")
            client.tls_set(ca_cert, certfile=cert_file, keyfile=key_file)
            client.tls_insecure_set(True)
        return client

    def disconnect(self, host):
        log.debug(f"Mqtt disconnect: {host}")
        client = self.get_client_by_host(host)
        if not client:
            return
        client.loop_stop()
        client.disconnect()
        self.clients.remove(client)

    def close(self):
        hosts = self.get_all_hosts()
        for host in hosts:
            self.disconnect(host)
        log.info(f"Mqtt disconnected hosts: {hosts}")

    def clean_messages(self, show_log=True):
        if show_log:
            log.info("Clean Mqtt messages")
        self.messages = []

    def get_messages(self):
        return self.messages[:]

    def add_message(self, message):
        self.messages.append(message)

    def set_max_messages(self, max_messages):
        self.max_messages = max_messages

    def get_bytes_length_from_json(self, json_output):
        """
        Calculate bytes length from JSON object which is parsed to payloads, then get length of bytes from payload
        Args:
            json_output: dict()

        Returns: int() length of bytes from payload

        """
        self.report_proto.Clear()
        parsed_pb = Parse(json.dumps(json_output), self.report_proto, ignore_unknown_fields=False)
        return sys.getsizeof(zlib.compress(parsed_pb.SerializeToString()))

    def publish(self, topic, msg, parse=True):
        """
        :param topic: topic string to which the client will publish
        :param msg: str or json format message in case parsing is set to True
        :param parse: if parse msg with protobuf template
        :return: mqtt publish output
        """
        if not self.clients:
            raise Exception("No client connected")
        if parse:
            message = self.mqtt_processing.pre_run(raw_msg=json.dumps(msg))
            parsed_pb = Parse(message, self.report_proto, ignore_unknown_fields=False)
            try:
                msg = parsed_pb.SerializeToString()
            except EncodeError as e:
                log.error(f"Cannot serialize mqtt message: {e}.\nMsg dump:\n{msg}")
                raise Exception("Cannot serialize mqtt message")

        self.clients[0].publish(topic, msg)


class MqttResolver:
    from string import Template
    import requests

    @staticmethod
    def get_mqtt_servers(hosts, node):
        """
        Get mqtt servers from zk configuration

        Args:
            hosts (list): list of zk hosts,
            node (str): path to zk node with mqtt servers,

        Returns:
            list of strings with address of mqtt servers
        """
        from lib.util.zookeeper import Zookeeper

        zk = Zookeeper()
        zk.connect_hosts(hosts)
        # TODO: Remove when all deployments have been moved to use emqtt
        # Temporary generic solution for resolving hosts until all deployments have been moved to use emqtt
        try:
            brokers = zk.get_children(node)
        except Exception as err:
            if "emqtt" not in node:
                raise Exception(err)
            node = node.replace("emqtt", "mqtt")
            brokers = zk.get_children(node)

        if "emqtt" in node:
            mqtt_servers = []
            for broker in brokers:
                info, stat = zk.get(node + "/" + broker)
                info = json.loads(info.decode())
                mqtt_servers.extend(info["localIpv4s"])
        else:
            if isinstance(brokers, list):
                mqtt_servers = brokers
            else:
                mqtt_servers = [brokers]

        zk.disconnect()
        return mqtt_servers

    @staticmethod
    def get_hosts(config):
        """
        Get mqtt servers from zookeeper
        Args:
            config: (dict) test bed config

        Returns: (list) mqtt_servers
        """
        servers = config.get("mqtt_servers", [])
        for server in servers[:]:
            if server == "rpi-server":
                servers.remove("rpi-server")
                servers.append(config["ssh_gateway"]["hostname"])
        if servers:
            return servers

        hosts = config.get("zk_hosts")
        nodes = config.get("zk_node")
        if not hosts or not nodes:
            raise Exception('Values of "mqtt_servers", "zk_hosts", "zk_node" not defined in config file')
        return MqttResolver.get_mqtt_servers(hosts, nodes)

    @staticmethod
    def get_statistic_topic(config, lid):
        """
        Generate stats topic
        Args:
            config: (dict) test bed config
            lid: (str) location id

        Returns: (str)  mqtt_topic
        """
        return MqttResolver.resolve_mqtt_topic(config, lid, config["topic_template"])

    @staticmethod
    def get_ip_threats_topic(config, device_id):
        return f'IP/Threats/{config["deployment_id"]}/{device_id}/#'

    @staticmethod
    def get_dns_queries_topic(config, device_id):
        return f'DNS/Queries/{config["deployment_id"]}/{device_id}/#'

    @staticmethod
    def get_sni_requests_topic(config, device_id):
        return f'SNI/Requests/{config["deployment_id"]}/{device_id}/#'

    @staticmethod
    def get_fcm_flows_topic(config, device_id, loc_id):
        return f'IP/Flows/{config["deployment_id"]}/{device_id}/{loc_id}'

    @staticmethod
    def get_wc_stats_topic(config, device_id, loc_id):
        return f'WC/Stats/Health/{config["deployment_id"]}/{loc_id}/{device_id}'

    @staticmethod
    def get_hero_stats_topic(config, device_id, loc_id):
        return f'WC/Stats/Hero/{config["deployment_id"]}/{loc_id}/{device_id}'

    @staticmethod
    def get_fcm_lan_stats_topic(config, loc_id):
        topic_template = "lan/$deployment/$locationId/$shard"
        return MqttResolver.resolve_mqtt_topic(config, loc_id, topic_template)

    @staticmethod
    def get_mdns_records_topic(config, device_id, loc_id):
        return f'MDNS/Records/{config["deployment_id"]}/{device_id}/{loc_id}'

    @staticmethod
    def get_interface_stats_topic(config, device_id, loc_id):
        return f'interfaceStats/{config["deployment_id"]}/{device_id}/{loc_id}'

    @staticmethod
    def get_time_events_topic(config, device_id, loc_id):
        return f'MqttLog/{config["deployment_id"]}/{device_id}/{loc_id}'

    @staticmethod
    def get_wifi_blaster_topic(config, device_id, loc_id):
        return f'WifiBlaster/{config["deployment_id"]}/{device_id}/{loc_id}'

    @staticmethod
    def get_adt_topic(config, device_id, loc_id):
        return f'DPI/ADT/{config["deployment_id"]}/{device_id}/{loc_id}'

    @staticmethod
    def get_dpi_stats_topic(config, device_id, loc_id):
        return f'DpiStats/{config["deployment_id"]}/{loc_id}/{device_id}'

    @staticmethod
    def resolve_mqtt_topic(config, lid, topic_template):
        dpl_id = config["deployment_id"]
        zk_hosts = config.get("zk_hosts")
        zk_node = config.get("zk_node")
        if not zk_hosts or not zk_node:
            raise Exception('Values of "mqtt_servers", "zk_hosts", "zk_node" not defined in config file')

        zk_node_base = zk_node[: zk_node.rfind(dpl_id) + len(dpl_id)]
        shard_id = MqttResolver.get_dynamic_shard(zk_node_base, dpl_id, lid)
        tpl = MqttResolver.Template(topic_template)
        topic = tpl.substitute(shard=shard_id, deployment=dpl_id, locationId=lid)
        return topic

    @staticmethod
    def get_dynamic_shard(zk_node_base, dpl_id, loc_id):
        shard_id = None
        if dpl_id == "dog1":
            dpl_name = "dogfood"
        else:
            dpl_name = dpl_id
        sharding_node = "infrastructure/services/sharding"
        zk_node = f"{zk_node_base}/{sharding_node}"
        from lib.util.zookeeper import Zookeeper

        zk = Zookeeper()
        zk.connect(dpl_name)
        sharding_service = json.loads(zk.get_node(zk_node).decode("utf-8"))
        sharding_url_base = sharding_service.get("privateUrl")
        sharding_user = sharding_service.get("user")
        sharding_passwd = sharding_service.get("password")
        if all([sharding_url_base, sharding_user, sharding_passwd]):
            auth = (sharding_user, sharding_passwd)
            sharding_url = f"{sharding_url_base}/locations/{loc_id}/shard"
            response = MqttResolver.requests.get(sharding_url, auth=auth)
            shard_str = json.loads(response.text).get("shardId")
            shard_id = shard_str.replace(f"{dpl_id}-", "")
        return shard_id


class MqttFakeStats:
    def __init__(self, publish_handler):
        self.publish_handler = publish_handler

    @staticmethod
    def assign_channels_to_bands(mqtt_message, channels):
        allowed_bands = [band["band"] for band in mqtt_message["survey"] if band.get("band")]
        bands = {band: [] for band in allowed_bands}
        # Assign channels to bands
        for channel in channels:
            assign_to_band = None
            if 1 <= channel <= 13:
                assign_to_band = bands.get("BAND2G")
            elif 36 <= channel <= 64:
                assign_to_band = bands.get("BAND5GL") if bands.get("BAND5GL") is not None else bands.get("BAND5G")
            elif 100 <= channel <= 165:
                assign_to_band = bands.get("BAND5GU") if bands.get("BAND5GU") is not None else bands.get("BAND5G")
            assert assign_to_band is not None, (
                f"Not found suitable band name for provided channel. " f"Allowed bands: {bands}"
            )
            assign_to_band.append(channel)
        return bands

    @staticmethod
    def get_allowed_channels(mqtt_message):
        allowed_channels = list()
        for survey in mqtt_message["survey"]:
            allowed_channels += [survey_data["channel"] for survey_data in survey["surveyList"]]
        return list(set(allowed_channels))

    def generate_fake_interference_at_channels(self, mqtt_message, pods_serial, channels, interference_level):
        """
        Generate fake interference on provided channels list.
        On rest of no provided channels set low interference level - 5%
        Args:
            mqtt_message: (dict) mqtt message
            pods_serial: (list) List of all pods serial to fake mqtt messages
            channels: (list) Channel list for manipulate interference level
            interference_level: (int) Interference level

        Returns: (List) List of mqtt with changed interference level

        """
        assert 0 < interference_level <= 100, "Incorrect level of interference." " Allowed interference range: 1-100"
        bands = self.assign_channels_to_bands(mqtt_message, channels)
        # Validate if provided 2.4G channels are allowed to fake
        allowed_channels = self.get_allowed_channels(mqtt_message)
        if bands["BAND2G"] and not [channel for channel in allowed_channels if channel in bands["BAND2G"]]:
            assert False, f'Provided incorrect channel of BAND2G, allowed channels: {bands["BAND2G"]}'

        fake_mqtt = list()
        pods_serial = pods_serial if isinstance(pods_serial, list) else [pods_serial]
        for pod_serial in pods_serial:
            mqtt_message["nodeID"] = pod_serial
            for survey in mqtt_message["survey"]:
                survey_band = survey["band"]
                channels_to_fake = bands[survey_band]
                for mqtt_survey in survey["surveyList"]:
                    # According to requirements from ticket, set low interference on no provided channels
                    # With except 5G bands, since there off channels are disabled,
                    # so we can send fake interference on whole band
                    if (
                        not channels_to_fake
                        or survey_band == "BAND2G"
                        and mqtt_survey["channel"] not in channels_to_fake
                    ):
                        mqtt_survey["busy"] = 5
                        mqtt_survey["busyRx"] = 5
                        continue
                    mqtt_survey["busy"] = interference_level
                    mqtt_survey["busyRx"] = interference_level
            # make sure there is a neighbor on the channels
            mqtt_neighbors_copy = mqtt_message["neighbors"][:]
            mqtt_message["neighbors"] = []
            for band in bands:
                if not bands[band]:
                    continue
                # in case requested band was not included in the original report, we need to add it
                all_reported_neighbors_bands = [neighbors_band["band"] for neighbors_band in mqtt_neighbors_copy]
                if band not in all_reported_neighbors_bands:
                    mqtt_message["neighbors"].append(
                        {
                            "band": band,
                            "scanType": "ONCHAN_SCAN",
                            "timestampMs": str(int(time.time() * 1000)),
                            "bssList": [],
                            "reportType": "RAW",
                        }
                    )
                width = "CHAN_WIDTH_40MHZ" if band == "BAND2G" else "CHAN_WIDTH_80MHZ"
                for channel in bands[band]:
                    for neighbors_band in mqtt_neighbors_copy:
                        if band not in neighbors_band["band"]:
                            continue
                        neighbors_band["bssList"].append(
                            {
                                "bssid": "08:f1:22:44:bb:15",
                                "chanWidth": width,
                                "channel": channel,
                                "rssi": 60,
                                "ssid": "fake_neighbour",
                            }
                        )
                        mqtt_message["neighbors"].append(neighbors_band)
            fake_mqtt.append(mqtt_message.copy())
        return fake_mqtt

    @staticmethod
    def generate_fake_traffic(pods_serial, mqtt_message, tx_bytes, rx_bytes):
        """
        Generate fake traffic on all provided pod list
        Args:
            pods_serial: (list) [(str)] Serial of pods where we want to generate fake mqtt message
            mqtt_message: (list) [(str)] Mqtt message
            tx_bytes: (str) Value of tx bytes
            rx_bytes: (str) Value of rx bytes

        Returns: (list) [(dict)] List of fake mqtt messages

        """
        mqtt_message = mqtt_message[-1]
        if not isinstance(mqtt_message, dict):
            mqtt_message = json.loads(mqtt_message)
        fake_mqtt = list()
        for pod_serial in pods_serial:
            mqtt_message["nodeID"] = pod_serial
            for client in mqtt_message["clients"]:
                for client_list in client["clientList"]:
                    client_list["stats"]["txBytes"] = tx_bytes
                    client_list["stats"]["rxBytes"] = rx_bytes
            fake_mqtt.append(mqtt_message.copy())
        return fake_mqtt

    @staticmethod
    def generate_fake_traffic_on_client(
        client_mac, parent_device, mqtt_messages, source_bhaul_channels, tx_bytes, rx_bytes
    ):
        """
        Generate fake traffic only on connected client
        Args:
            client_mac: (str) client mac of connected client to network
            parent_device: (str) id of device where is connected client
            mqtt_messages: (list) list of messages to fake traffic
            source_bhaul_channels: (dict) dict of source bhaul channels {source_id: bhaul_channel, ...}
            tx_bytes: (int)
            rx_bytes: (int)

        Returns:

        """

        def _is_backhaul_ssid(ssid: str) -> bool:
            if ssid.startswith("we.") and len(ssid) in [10, 11]:
                return True
            return False

        # Put fake traffic to the device where client is connected
        for mqtt_msg in mqtt_messages:
            if mqtt_msg["nodeID"] != parent_device:
                continue
            for clients in mqtt_msg["clients"]:
                for client in clients["clientList"]:
                    if client_mac.upper() != client["macAddress"].upper():
                        continue
                    client["stats"]["txBytes"] = tx_bytes
                    client["stats"]["rxBytes"] = rx_bytes

        # Put fake traffic to the bhaul stats of the source device
        for source_device, bhaul_channel in source_bhaul_channels.items():
            for mqtt_msg in mqtt_messages:
                if mqtt_msg["nodeID"] != source_device:
                    continue
                for clients in mqtt_msg["clients"]:
                    if clients["channel"] != bhaul_channel:
                        continue
                    for client in clients["clientList"]:
                        if not _is_backhaul_ssid(client["ssid"]):
                            continue
                        client["stats"]["txBytes"] = tx_bytes
                        client["stats"]["rxBytes"] = rx_bytes
        return mqtt_messages

    @staticmethod
    def generate_fake_interference_msg(pods_serial, mqtt_message, busy, bands=None):
        """
        Method for generate fake interference
        Args:
            pods_serial: (list) [(str)] Serial of pods where we want to generate fake mqtt message
            mqtt_message: (list) [(str)] Mqtt message
            bands: (list) Bands where we want to generate fake mqtt message 5G or 2G or all
            busy: (int) Interference in percents scope: 0 - 100
        Returns: (list) [(dict)] List of fake mqtt messages

        """
        if not bands:
            bands = ["2G", "5G"]

        fake_mqtt = list()
        mqtt_message = mqtt_message[-1]
        if not isinstance(mqtt_message, dict):
            mqtt_message = json.loads(mqtt_message)
        for pod_serial in pods_serial:
            mqtt_message["nodeID"] = pod_serial
            for survey in mqtt_message["survey"]:
                for band in bands:
                    if band in survey["band"]:
                        for interference in survey["surveyList"]:
                            interference["busy"] = busy
                            interference["busyRx"] = busy
            fake_mqtt.append(mqtt_message.copy())
        return fake_mqtt

    @staticmethod
    def generate_fake_rssi_msg(device, mqtt_messages, bhaul_channel, device_macs, snr_level=0, noise_floor=0):
        """
        Generate fake rssi base on provided SNR and NoiseFloor level. Formula: RSSI = NoiseFloor - SNR
        Required is at least one of arg to generate fake msg: snr_level or noise_floor
        Args:
            device: (str) ID of target device to change rssi stats
            mqtt_messages: (list) List of mqtt messages [parent_device_msg, target_device_msg]
            bhaul_channel: (int) Bhaul channel number between parent and target device
            device_macs: (list) List of all macs from device
            snr_level: (int) SNR level
            noise_floor: (int) Noise Floor level

        Returns:

        """
        assert snr_level or noise_floor, "Did not provide any arg to generate fake mqtt"

        for mqtt_message in mqtt_messages:
            node_id = mqtt_message["nodeID"]
            if snr_level:
                for mqtt_client in mqtt_message["clients"]:
                    if bhaul_channel != mqtt_client["channel"]:
                        continue
                    for client in mqtt_client["clientList"]:
                        if (
                            node_id != device.upper()
                            and client["macAddress"].upper() not in device_macs
                            and device.upper() != client["macAddress"].upper()
                        ):
                            continue
                        client["stats"]["rssi"] = snr_level

                for neighbor in mqtt_message["neighbors"]:
                    for bss in neighbor.get("bssList", []):
                        bssid = bss["bssid"].upper()
                        if bssid not in device_macs and device.upper() != bssid and node_id != device.upper():
                            continue
                        min_snr_level = snr_level - 4 if snr_level >= 6 else snr_level
                        neighbor_snr = random.randint(min_snr_level, snr_level)
                        bss["rssi"] = neighbor_snr
            if noise_floor:
                for mqtt_survey in mqtt_message["survey"]:
                    for survey in mqtt_survey["surveyList"]:
                        if survey["channel"] != bhaul_channel:
                            continue
                        if not survey.get("noiseFloor"):
                            survey.update({"noiseFloor": noise_floor})
                        else:
                            survey["noiseFloor"] = noise_floor
        return mqtt_messages

    def publish_fake_mqtt(self, fake_mqtt_msg, mqtt_topic, timeout=15, msg_delay=60):
        """
        Publishing fake mqtt messages every minute
        Args:
            fake_mqtt_msg: (list) [(dict)] List of fake mqtt messages generate for example from
                generate_fake_interference() method
            mqtt_topic: (str) from generated mqtt servers
            timeout: (int) Timeout for how long to generate fake interference. Default 15 minutes
            msg_delay: (int) Sleep between messages. Default 60 sec

        Returns: None

        """

        log.info("Publishing fake mqtt messages every minute")
        max_time = time.time() + (timeout * 60)
        msg_counter = 0
        while time.time() < max_time:
            fake_mqtt_msg = self.update_timestamp(fake_mqtt_msg)
            for fake_msg in fake_mqtt_msg:
                self.publish_handler(mqtt_topic, fake_msg)
            msg_counter += 1
            log.info(f"Mqtt fake messages: {msg_counter}")
            time.sleep(msg_delay)

    @staticmethod
    def update_timestamp(mqtt_msgs):
        current_timestamp_ms = int(round(time.time() * 1000))
        for mqtt_msg in mqtt_msgs:
            for client in mqtt_msg.get("clients", []):
                client["timestampMs"] = current_timestamp_ms
            for neighbor in mqtt_msg.get("neighbors", []):
                neighbor["timestampMs"] = current_timestamp_ms
            for survey in mqtt_msg.get("survey", []):
                survey["timestampMs"] = current_timestamp_ms
        return mqtt_msgs


class MqttLogCatcher(LogCatcher):
    def __init__(self, obj, **kwargs):
        super().__init__(**kwargs)
        self.obj = obj

    def add(self, msg):
        new_msg = "=" * 80 + "\n"
        msg_tmp = msg.copy()
        if msg.get("nodeID"):
            new_msg += f"nodeID: {msg_tmp['nodeID']}\n"
            del msg_tmp["nodeID"]
        columns = 160
        new_msg += JsonPrettyPrinter(indent=1, width=columns).pformat(msg_tmp)
        self.add_to_logs(new_msg)

    def collect(self, test_data):
        pass


# The protobuf json_format method translates bytes arrays in base64 encoded string for a few specific topics.
# This method translates such strings in their expected form
# (mac address, IP address)
class MqttProcessing:
    def __init__(self, mqtt_lib):
        self.mqtt_lib = mqtt_lib
        self.process_cfg = self.load_process_cfg()

    def post_run(self, raw_msg):
        """
        Decode values after receiving a message
        """
        proto_report_name = self.get_proto_report_name()
        if proto_report_name not in self.process_cfg.keys():
            return raw_msg
        post_process_topic = self.process_cfg[proto_report_name]
        for item_to_translate, values in post_process_topic.items():
            for value in values:
                translate_function = getattr(self, f"translate_{item_to_translate}", None)
                if not translate_function:
                    continue
                raw_msg = translate_function(value, raw_msg)
        return raw_msg

    def pre_run(self, raw_msg):
        """
        Encode values after receiving a message
        """
        proto_report_name = self.get_proto_report_name()
        if proto_report_name not in self.process_cfg.keys():
            return raw_msg
        post_process_topic = self.process_cfg[proto_report_name]
        for item_to_translate, values in post_process_topic.items():
            for value in values:
                translate_function = getattr(self, f"encode_{item_to_translate}", None)
                if not translate_function:
                    continue
                raw_msg = translate_function(value, raw_msg)
        return raw_msg

    @staticmethod
    def load_process_cfg():
        post_process_path = os.path.join(BASE_DIR, "lib_testbed", "generic", "mqtt", "post_processing.json")
        with open(post_process_path) as post_process_cfg:
            post_process_cfg = json.load(post_process_cfg)
        return post_process_cfg

    def get_proto_report_name(self):
        return self.mqtt_lib.report_proto.DESCRIPTOR.name

    @staticmethod
    def translate_mac_address(key_to_translate, raw_msg):
        regex_result = re.findall(f'"{key_to_translate}": (".*?")', raw_msg)
        if not regex_result:
            return raw_msg
        for encoded_mac in regex_result:
            base64_mac = bytearray(base64.b64decode(encoded_mac))
            mac_bytes = [hex(a)[2:].zfill(2) for a in list(base64_mac)]
            mac = ":".join(mac_bytes)
            raw_msg = raw_msg.replace(encoded_mac, f'"{mac}"')
        return raw_msg

    @staticmethod
    def encode_mac_address(key_to_translate, raw_msg):
        regex_result = re.findall(f'"{key_to_translate}": (".*?")', raw_msg)
        if not regex_result:
            return raw_msg
        for encoded_mac in regex_result:
            encoded_mac_ = encoded_mac.replace('"', "")
            ret = [int(_byte, 16) for _byte in encoded_mac_.split(":")]
            base64_mac = str(base64.b64encode(bytearray(ret)).decode())
            raw_msg = raw_msg.replace(encoded_mac, f'"{base64_mac}"')
        return raw_msg

    @staticmethod
    def translate_ipv4_address(key_to_translate, raw_msg):
        regex_result = re.findall(f'"{key_to_translate}": ' + r"(\d+)", raw_msg)
        if not regex_result:
            return raw_msg
        for encoded_ipv4_address in regex_result:
            decoded_ipv4 = socket.inet_ntop(socket.AF_INET, int(encoded_ipv4_address).to_bytes(4, byteorder="big"))
            raw_msg = raw_msg.replace(encoded_ipv4_address, f'"{decoded_ipv4}"')
        return raw_msg

    @staticmethod
    def translate_ipv6_address(key_to_translate, raw_msg):
        regex_result = re.findall(f'"{key_to_translate}": (".*?")', raw_msg)
        if not regex_result:
            return raw_msg
        for encoded_ipv6_address in regex_result:
            ipv6_bytes = bytearray(base64.b64decode(encoded_ipv6_address))
            decoded_ipv6 = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
            raw_msg = raw_msg.replace(encoded_ipv6_address, f'"{decoded_ipv6}"')
        return raw_msg

    @staticmethod
    def encode_ipv6_address(key_to_translate, raw_msg):
        regex_result = re.findall(f'"{key_to_translate}": (".*?")', raw_msg)
        if not regex_result:
            return raw_msg
        for encoded_ipv6_address in regex_result:
            encoded_ipv6_address_ = encoded_ipv6_address.replace('"', "")
            base64_addr = str(base64.b64encode(ipaddress.IPv6Address(encoded_ipv6_address_).packed).decode())
            raw_msg = raw_msg.replace(encoded_ipv6_address, f'"{base64_addr}"')
        return raw_msg

    @staticmethod
    def translate_encoded_string(key_to_translate, raw_msg):
        regex_result = re.findall(f'"{key_to_translate}": (".*?")', raw_msg)
        if not regex_result:
            return raw_msg
        for encoded_string in regex_result:
            decoded_string = base64.b64decode(encoded_string).decode()
            # Skip control characters
            decoded_string = "".join([i for i in decoded_string if unicodedata.category(i) != "Cc"])
            raw_msg = raw_msg.replace(encoded_string, f'"{decoded_string}"')
        return raw_msg
