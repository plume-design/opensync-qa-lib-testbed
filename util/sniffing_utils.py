import pathlib
import uuid
import time
import os
import allure
import pyshark

from pyshark.packet import packet

from lib_testbed.generic.client.models.generic.client_api import ClientApi
from lib_testbed.generic.util.common import threaded
from lib_testbed.generic.util.logger import log


def start_sniffer_on_client(client_obj: ClientApi, channel: int) -> tuple[str, str]:
    """Generates a unique sniff file name, turns client into Wi-Fi monitor,
    starts sniffing with ``tcpdump``. Return sniff file name and path to file on the sniffer"""
    sniff_file_name = uuid.uuid4().hex
    remote_sniff_file_path = f"/tmp/{sniff_file_name}"
    try:
        log.info("Starting sniffing on client %s, channel %s", client_obj.nickname, channel)
        client_obj.wifi_monitor(channel)
        client_obj.run(f"tcpdump -U -i {client_obj.ifname} -w {remote_sniff_file_path} > /tmp/log_tcpdump.txt 2>&1 &")
    except Exception:
        log.info(f"Something went wrong, restoring {client_obj.nickname} into station mode")
        client_obj.run("killall tcpdump", skip_exception=True)
        client_obj.wifi_station(skip_exception=True)
    return sniff_file_name, remote_sniff_file_path


def stop_sniffer_and_get_file(
    client_obj: ClientApi,
    remote_sniff_file_path: str | pathlib.Path,
    tmp_path: pathlib.Path,
    check_file_size: bool = True,
) -> pathlib.Path:
    """Closes tcpdump, pulls the capture file from remote_sniff_file_path to the local temp file.
    Returns path to the local file"""
    log.info("Stopping sniffer")
    client_obj.run("killall tcpdump", skip_exception=True)
    client_obj.wifi_station(skip_exception=True)
    log.info(
        "Downloading file from client %s: %s to local path: %s",
        client_obj.nickname,
        remote_sniff_file_path,
        tmp_path,
    )
    client_obj.get_file(remote_sniff_file_path, tmp_path)
    client_obj.run(f"rm -rf {remote_sniff_file_path}", skip_exception=True)
    local_sniff_file_path = tmp_path / client_obj.nickname / remote_sniff_file_path.split("/")[-1]
    if check_file_size:
        sniff_size = os.path.getsize(local_sniff_file_path)
        assert sniff_size > 25, "Sniff file is empty"
    return local_sniff_file_path


def sniff_packets_on_client(
    client_obj: ClientApi, channel: int, tmp_path: pathlib.Path, timeout: int = 10
) -> pathlib.Path:
    """Generates a unique sniff file name, turns client into Wi-Fi monitor,
    starts sniffing with ``tcpdump``, waits given timeout. Makes sure to
    close tcpdump after timeout is reached, pulls the dump file to the local
    temp file."""

    sniff_file_name, remote_sniff_file_path = start_sniffer_on_client(client_obj, channel)
    log.info(f"Waiting requested {timeout} sec...")
    time.sleep(timeout)
    local_sniff_file_path = stop_sniffer_and_get_file(client_obj, remote_sniff_file_path, tmp_path)
    return local_sniff_file_path


def load_pyshark_packets(file_path: str | pathlib.Path, pyshark_filter: str) -> list[packet.Packet]:
    """Utility function to log and load sniffed packets using pyshark"""
    log.info("Pyshark filter: %s", pyshark_filter)
    packets = parse_capture_file(str(file_path), display_filter=pyshark_filter, only_summaries=False)
    log.info("Captured %s packets matching the filter", len(packets))
    return packets


def parse_capture_file(*args, **kwargs) -> list[packet.Packet]:
    """
    Return list of pyshark packets parsed from pcap file.

    The file is parsed in a separate thread, to not interfere with main thread signal handling.

    Args:
        *args, **kwargs: Same args that are accepted by pyshark.FileCapture

    Returns: (list) of packets found in pcap file
    """
    future = _parse_capture_file(*args, **kwargs)
    return future.result()


@threaded
def _parse_capture_file(*args, **kwargs):
    with pyshark.FileCapture(*args, **kwargs) as capture:
        return list(capture)


def attach_capture_file_to_allure(file_path: str | pathlib.Path) -> None:
    """
    Attaches sniff file to the Allure report
    """
    allure.attach.file(file_path, "sniff_capture.pcap", allure.attachment_type.PCAP)
