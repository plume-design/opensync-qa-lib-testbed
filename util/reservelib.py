import os
import sys
import traceback
import time
import pytest
import uuid
import inspect
import datetime
import threading
import queue
import yaml
import functools

from lib_testbed.generic.util.logger import log, LogCatcher
from lib_testbed.generic.util.common import BASE_DIR
from lib_testbed.generic.util import config
from lib_testbed.generic.client.client import Clients

SSH_GATEWAY = "ssh_gateway"
RESERVELIB_OUT_FILE = "log_reservelib"


class ReserveLib:
    def __init__(self, **kwargs):
        self.tb_config = kwargs.get("config")
        self.json_output = kwargs.get("json")
        self.new_reservation_msg = self.tb_config.get("message")
        self.tb_name = config.get_location_name(self.tb_config)
        self.res_file = f"/.reserve_{self.tb_name}"
        self.machine_uuid = self._get_machine_uuid()
        self.client_lib = self._get_client_lib()
        self.openfd_cmd = "sudo touch " + self.res_file + "; exec {reservefd}<" + self.res_file + ";"
        self.closefd_cmd = "exec {reservefd}<&-"

    def _tb_purpose_decorator(func):
        """
        Check location config file for existing of 'purpose' key
        insert key value pair into func's returned dictionary if present
        Args:
            func: (callable) - function to be decorated (implicit)

        Returns: (callable) - wrapped function w/ updated dictionary
        """

        def wrapped_func(self, *args, **kwargs):
            func_dict = func(self, *args, **kwargs)
            purpose = self.tb_config.get("purpose", "-")
            func_dict.update({"purpose": purpose})
            return func_dict

        functools.update_wrapper(wrapped_func, func)
        return wrapped_func

    def _existing_msg_decorator(func):
        """
        Check tb reservation file for reservation message sring
        insert key value pair into func's returned dictionary if k,v pair present
        Args:
            func: (callable) - function to be decorated (implicit)

        Returns: (callable) - wrapped function w/ updated dictionary
        """

        def wrapped_func(self, *args, **kwargs):
            rsrv_msg = self._get_crnt_reservation_msg()
            func_dict = func(self, *args, **kwargs)
            rsrv_msg = rsrv_msg if rsrv_msg else "-"
            func_dict.update({"reservation message": rsrv_msg})
            return func_dict

        functools.update_wrapper(wrapped_func, func)
        return wrapped_func

    def _get_client_lib(self):
        """
        Get client object
        """
        config = self.tb_config
        kwargs = {"config": config, "multi_obj": True, "nicknames": ["host"]}
        try:
            clients_obj = Clients(**kwargs)
            clients_api = clients_obj.resolve_obj(**kwargs)
            client_lib = clients_api.lib
            return client_lib
        except Exception:
            traceback.print_exc(limit=2, file=sys.stdout)
            raise

    def _server_ssh_call(self, command, timeout=10, **kwargs):
        """
        Basic method for communication with ssh_gateway
        Args:
            command: (str) command to execute

        Returns: (byte) subprocess output. Raises exception in case of error
        """
        kwargs.update({"timeout": timeout})
        ret = self.client_lib.run_command(command, skip_logging=True, **kwargs)[0]
        if ret[0]:
            return f"Error: {ret[2]}"
        return ret[1].strip()

    def _system_qa_rsrv_exemption(self):
        """
        Evaluates the presence of '-f' cli flag, or substring 'systemqa' within TB config file's 'purpose' param

        Returns: (bool) - True if '-f' flag present, or 'systemqa' in location file's 'purpose' key string
        """
        systemqa_tb_str = "systemqa" in self.tb_config.get("purpose", "").lower()
        return systemqa_tb_str or self.tb_config.get("force")

    def _get_crnt_reservation_msg(self):
        """
        Checks reservation file for the presence of a reservation message (appended to end of timestamp)

        Returns: (str) - Existing message string appended to end of reservation line
        """
        message = ""
        try:
            file_operation_cmds = f'flock -x "$reservefd"; ' f"tail -1 {self.res_file}; " f"sync; "
            cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd

            out = self._server_ssh_call(cmd)
        except Exception as error:
            log.error(f"Failed to parse reservation log -> {error}")
            out = ""
        if "__" in out:
            info = out.split("__")
            message_raw = info[3].split() if len(info) > 3 else []
            if len(message_raw) > 1:
                message = " ".join(message_raw[1:]).replace("(", "").replace(")", "")
        return message

    @_tb_purpose_decorator
    def reserve_test_bed(self, timeout=120):
        """
        Reserve test bed. Default timeout is 120 minutes
        """
        if not self.check_reservation_possible():
            return {
                "name": self.tb_name,
                "status": False,
                "owner": "CANNOT RESERVE THIS TB",
                "since": "-",
                "expiration": "-",
            }
        if type(timeout) is not int:
            timeout = int(timeout)
        status = self.get_reservation_status(tool=False)
        log_catcher.process_caller(inspect.stack()[1][3], status)
        if not self.tb_config.get("force"):
            # check if we can reserve test bed
            log.debug("Checking if testbed if not reserved")
            if status["busy"] and not status["busyByMe"]:
                log.error(f"{self.tb_name} is used by {status['owner']}." f" Expires at: {status['expiration']}")
                return {
                    "name": self.tb_name,
                    "status": False,
                    "owner": status["owner"],
                    "since": f"{status['since']}",
                    "expiration": f"{status['expiration']}",
                }

        # limit the file to 2000 lines
        # this is the most problematic part, which often corrupts reservation file, so do it before adding new line
        file_operation_cmds = f'flock -x "$reservefd"; ' f"tail -2000 {self.res_file} | tee {self.res_file}; " f"sync; "
        cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd
        self._server_ssh_call(cmd)

        # TODO: in case of force, previous reservation should end and new start
        res_row = self.generate_reservation_row(status, timeout)
        # in case tb is reserved by Me, just update last row -> so delete it first
        if status["busyByMe"]:
            file_operation_cmds = (
                f'flock -x "$reservefd"; '
                f'sudo sed -i "$ d" {self.res_file}; '
                f'echo "{res_row}" | sudo tee -a {self.res_file}; '
                f"sync; "
            )
        else:
            file_operation_cmds = (
                f'flock -x "$reservefd"; ' f'echo "{res_row}" | sudo tee -a {self.res_file}; ' f"sync; "
            )

        cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd
        out = self._server_ssh_call(cmd)
        if out.startswith("Error:"):
            return {
                "name": self.tb_name,
                "status": False,
                "owner": "ERROR: CANNOT RESERVE",
                "since": status["since"],
                "expiration": "-",
            }

        res_row = res_row.split("__")
        # remove msg from res_row[3] - if msg exists
        if len(res_row[3].split()) > 1:
            res_row[3], *self.new_reservation_msg = res_row[3].split()
            self.new_reservation_msg = " ".join(self.new_reservation_msg).replace("(", "").replace(")", "")
        rsrv_dict = {
            "name": self.tb_name,
            "status": True,
            "owner": res_row[0],
            "since": f"{self._convert_utc_to_local(res_row[2])}",
            "expiration": f"{self._convert_utc_to_local(res_row[3])}",
        }
        if self.new_reservation_msg:
            rsrv_dict.update({"reservation message": self.new_reservation_msg})
        return rsrv_dict

    @_existing_msg_decorator
    @_tb_purpose_decorator
    def get_reservation_status(self, tool=True):
        """
        Check reservation status
        """
        if not self.check_reservation_possible():
            return {
                "name": self.tb_name,
                "busy": False,
                "busyByMe": False,
                "owner": "CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
            }
        file_operation_cmds = f'flock -x "$reservefd"; ' f"tail -1 {self.res_file}; "

        cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd

        out = self._server_ssh_call(cmd)

        if not out:
            file_operation_cmds = f'flock -x "$reservefd"; ' f"[ -s {self.res_file} ] || echo empty file; "
            cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd

            out = self._server_ssh_call(cmd)
            if out != "empty file":
                return {
                    "name": self.tb_name,
                    "busy": False,
                    "busyByMe": False,
                    "owner": "CANNOT GET RESERVATION",
                    "since": "-",
                    "expiration": "-",
                }
        # analyze case where file does not exist
        if "No such file or directory" in out or "cannot open lock file" in out or "empty file" in out:
            return {
                "name": self.tb_name,
                "busy": False,
                "busyByMe": False,
                "owner": "NO RESERVATION FILE",
                "since": "-",
                "expiration": "-",
            }
        # analyze other exceptions
        if out.startswith("Error:") or "__" not in out:
            return {
                "name": self.tb_name,
                "busy": False,
                "busyByMe": False,
                "owner": "CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
            }
        # analyze the last row of reservation file
        info = out.split("__")
        # gather existing reservation message, if it exists - split apart timestamp from initial part of line
        try:
            if len(info[3].split()) > 1:
                info[3] = info[3].split()[0]
            busy = datetime.datetime.utcnow() < datetime.datetime.fromisoformat(info[3])
        except (ValueError, IndexError) as error:
            busy = None
            log.error(f"Invalid timestamp in reservation file -> {error}")
        if len(info) != 4 or busy is None:
            log.error("Reservation file is corrupted, removing last reservation")
            file_operation_cmds = f'flock -x "$reservefd"; ' f'sudo sed -i "$ d" {self.res_file}; ' f"sync;"
            cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd

            self._server_ssh_call(cmd)
            return {
                "name": self.tb_name,
                "busy": False,
                "busyByMe": False,
                "owner": "CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
            }
        busy_by_me = busy and self._get_machine_uuid() == info[1]
        # nicer look of the date
        if tool:
            info[2] = self._convert_utc_to_local(info[2])
            info[3] = self._convert_utc_to_local(info[3])
        if busy:
            return {
                "name": self.tb_name,
                "busy": busy,
                "busyByMe": busy_by_me,
                "owner": info[0],
                "since": f"{info[2]}",
                "expiration": f"{info[3]}",
            }
        else:
            info[3] = f"Expired: {info[3]}" if tool else "-"
            return {
                "name": self.tb_name,
                "busy": busy,
                "busyByMe": busy_by_me,
                "owner": f"Last owner: '{info[0]}'",
                "since": "-",
                "expiration": info[3],
            }

    def unreserve(self):
        """
        Un-reserve test bed
        """
        if not self.check_reservation_possible():
            return {
                "name": self.tb_name,
                "busy": False,
                "busyByMe": False,
                "owner": "CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
            }
        status = self.get_reservation_status(tool=False)
        log_catcher.process_caller(inspect.stack()[1][3], status)
        # if cannot get reservation notify about that
        if status["owner"] == "CANNOT GET RESERVATION":
            return {
                "name": self.tb_name,
                "status": False,
                "owner": "ERROR: CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
            }

        # if not reserved just exit
        if not status["busy"]:
            return {"name": self.tb_name, "status": True, "owner": "-", "since": "-", "expiration": "-"}

        if not self.tb_config.get("force"):
            # check if we can un-reserve test bed
            log.info("Checking if tb is reserved by me")
            if status["busy"] and not status["busyByMe"]:
                log.error(f"{self.tb_name} is used by '{status['owner']}'. Expires at: {status['expiration']}")
                return {
                    "name": self.tb_name,
                    "status": False,
                    "owner": status["owner"],
                    "since": f"{status['since']}",
                    "expiration": f"{status['expiration']}",
                }

        # in case of force, we need to keep owner
        res_row = self.generate_reservation_row(status, 0, keep_owner=True)

        file_operation_cmds = (
            f'flock -x "$reservefd"; '
            f'sudo sed -i "$ d" {self.res_file}; '
            f'echo "{res_row}" | sudo tee -a {self.res_file}; '
            f"sync;"
        )
        cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd
        out = self._server_ssh_call(cmd)

        if out.startswith("Error:"):
            return {
                "name": self.tb_name,
                "status": False,
                "owner": "ERROR: CANNOT UNRESERVE",
                "since": status["since"],
                "expiration": "-",
            }
        res_row = res_row.split("__")
        return {
            "name": self.tb_name,
            "status": True,
            "owner": "-",
            "since": f"{self._convert_utc_to_local(res_row[2])}",
            "expiration": "-",
        }

    def clear_reservation_history(self):
        """
        Clear reservation history (remove reservation file)
        """
        if not self.check_reservation_possible():
            return {"name": self.tb_name, "status": False, "msg": "RESERVATION NOT POSSIBLE"}
        status = self.get_reservation_status(tool=False)
        log_catcher.process_caller(inspect.stack()[1][3], status)
        # if reserved, keep the last line
        if status["busy"]:
            file_operation_cmds = (
                f'flock -x "$reservefd"; ' f'echo "$(tail -1 {self.res_file})" | sudo tee {self.res_file}; ' f"sync;"
            )
            cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd

            out = self._server_ssh_call(cmd)
        else:
            out = self._server_ssh_call(f"sudo rm {self.res_file}; sync")
        if "Error" in out:
            return {"name": self.tb_name, "status": False, "msg": "CLEARING ERROR"}
        else:
            return {"name": self.tb_name, "status": True, "msg": "DONE"}

    def usage_statistics(self, time_res="week", min_use="0"):  # noqa: C901
        """
        Get test bed usage statistics; time_res=week|month|year
        """
        assert time_res in ["week", "month", "year"]
        assert min_use.isdigit()
        min_use = int(min_use)
        ret = {"name": self.tb_name}
        if min_use:
            ret["in_use"] = "-"
        if not self.check_reservation_possible():
            ret["stats"] = "RESERVATION NOT POSSIBLE"
            return ret

        if time_res == "week":
            delta = 7
        elif time_res == "month":
            delta = 30
        else:
            delta = 365

        file_operation_cmds = f'flock -x "$reservefd"; ' f"cat {self.res_file}; "
        cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd

        out = self._server_ssh_call(cmd)
        if not out or "returned non-zero exit status 1" in out or "returned non-zero exit status 66" in out:
            ret["stats"] = self._generate_stats_print(time_res, 0, 0)
            if min_use:
                ret["in_use"] = False
            return ret
        if "returned non-zero exit status 255" in out:
            ret["stats"] = "CANNOT GET RESERVATION"
            return ret
        if "No such file or directory" in out or "cannot open lock file" in out or "empty file" in out:
            ret["stats"] = "NO RESERVATION DATA"
            return ret
        if out.startswith("Error:"):
            ret["stats"] = "CANNOT REACH TB"
            return ret

        boundary = datetime.datetime.utcnow() - datetime.timedelta(days=delta)
        res_count = 0
        res_time = 0
        for line in out.split("\n")[::-1]:
            log.info(line)
            reservation = line.split("__")
            if len(reservation) < 4:
                if line:  # report it, unless it's just an empty line
                    log.warning(f'Invalid reservation line for {self.tb_name}: "{line}"')
                continue
            st_res = datetime.datetime.fromisoformat(reservation[2])
            end_res = datetime.datetime.fromisoformat(reservation[3].split()[0])  # split handles reservation messages
            if end_res < boundary:
                # latest reservation is earlier than boundary, so there is nothing to analyze above
                break
            res_count += 1
            # if reservation started before boundary, use boundary as reservation starting point
            if st_res < boundary:
                st_res = boundary
            # if reservation ends after current time, stop NOW
            if end_res > datetime.datetime.utcnow():
                end_res = datetime.datetime.utcnow()
            res_time += (end_res - st_res).days * 24 * 3600 + (end_res - st_res).seconds
        if min_use:
            ret["in_use"] = res_count >= min_use
        ret["stats"] = self._generate_stats_print(time_res, res_count, res_time)
        return ret

    @staticmethod
    def _generate_stats_print(time_res, times=None, occupancy=None):
        if times is not None:
            times = f" {times} times"
        if occupancy is not None:
            occupancy = datetime.timedelta(seconds=occupancy)
            occupancy = f" in use for: {occupancy} [H:M:S]"
        if times and occupancy:
            times += ","
        return f"last {time_res} reserved:{times}{occupancy}"

    def check_reservation_possible(self):
        """
        Check if reservation is possible by checking if ssh_gateway is provided in config
        Returns: (bool) True/False

        """
        if not self.tb_config.get(SSH_GATEWAY):
            log.warning(f'Missing "{SSH_GATEWAY}" for {self.tb_name}, reservation not possible')
            return False
        return True

    def generate_reservation_row(self, current_reservation, reservation_time=120, keep_owner=False):
        """
        Generate reservation file name
        Args:
            current_reservation: (dict) current reservation
            reservation_time: (int) timeout for test bed reservation
            keep_owner: (bool) return the same owner (needed in case of force)

        Returns: (str) reservation file row:
            "<hostname_or_job>[-<build_number>]__<machine_uuid>__<start_time>__<end_time> <reservation_message>"

        """
        max_reserv_time = 3 * 24 * 60
        if not self._system_qa_rsrv_exemption():
            assert reservation_time <= max_reserv_time, f"Max reservation time is {max_reserv_time} minutes"

        if not (host_name := os.environ.get("CUSTOM_HOSTNAME")):
            host_name = os.uname()[1]

        if host_name.endswith("-docker"):
            host_name = host_name[: -len("-docker")]  # strip '-docker' from the end of the hostname

        if keep_owner:
            file_operation_cmds = f'flock -x "$reservefd"; ' f"tail -1 {self.res_file};"
            cmd = self.openfd_cmd + file_operation_cmds + self.closefd_cmd

            out = self._server_ssh_call(cmd)
            assert out and "Error" not in out
            out = out.split("__")
            owner = out[0]
            mach_uuid = out[1]
        elif os.environ.get("JOB_NAME"):
            build_number = f"-{os.environ.get('BUILD_NUMBER')}" if os.environ.get("BUILD_NUMBER") else ""
            job_name = os.environ.get("JOB_NAME")
            owner = f"{job_name}{build_number}"
            if not self.new_reservation_msg:
                if build_number:
                    # we have both job_name and build_number -- we were most probably started by Jenkins
                    self.new_reservation_msg = f"Jenkins job on {host_name}"
                else:
                    # just job_name, possibly exported by a user -- use a more generic "<job_name> on <host>"
                    self.new_reservation_msg = f"{job_name} on {host_name}"
            mach_uuid = self.machine_uuid
        else:
            build_number = f"-{os.environ.get('BUILD_NUMBER')}" if os.environ.get("BUILD_NUMBER") else ""
            owner = f"{host_name}{build_number}"
            mach_uuid = self.machine_uuid

        start_time = current_reservation.get("since")
        if start_time == "-":
            start_time = datetime.datetime.utcnow().isoformat()

        end_time = current_reservation.get("expiration")
        if end_time == "-":
            end_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=reservation_time)
        else:
            # pytest extends reservation by 10 or 3, in case there is existing longer reservation probably it's manual,
            # so keep the original record
            end_time = datetime.datetime.fromisoformat(end_time)
            if not (
                reservation_time in [10, 3] and datetime.datetime.utcnow() + datetime.timedelta(minutes=10) < end_time
            ):
                end_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=reservation_time)

        rsrv_msg = f" ({self.new_reservation_msg})" if self.new_reservation_msg else ""
        return f"{owner}__{mach_uuid}__{start_time}__{end_time.isoformat()}{rsrv_msg}"

    @staticmethod
    def _get_machine_uuid():
        """
        Generate unique machine UUID
        Returns: (str) machine uuid
        """
        return f"{str(uuid.UUID(int=uuid.getnode())).split('-')[-1]}{os.environ.get('BUILD_NUMBER', '')}"

    @staticmethod
    def _convert_utc_to_local(utc_time):
        """
        Converts utc time to local
        Args:
            utc_time: (str) timestamp in ISO format

        Returns: (str)

        """
        utc_time = datetime.datetime.fromisoformat(utc_time)
        now_timestamp = time.time()
        offset = datetime.datetime.fromtimestamp(now_timestamp) - datetime.datetime.utcfromtimestamp(now_timestamp)
        log.debug(f"UTC offset: {offset}")
        return datetime.datetime.strftime(utc_time + offset, "%Y-%m-%d %H:%M:%S")


# keeping that global, so other plugins can stop the reservation threat, e.g PyUpgradePlugin
reserve_main_q = {}
lock = threading.Lock()


class PyReservePlugin:
    def __init__(self, config_name, tb_pool_name, skip_reservation, tb_config=None):
        assert config_name or tb_pool_name, "Cannot be used without config file or testbed pool name"
        self.config_name = config_name
        self.tb_pool_name = tb_pool_name
        self.skip_reservation = skip_reservation
        self.reserve_t = None
        self.res = None
        self.tb_config = tb_config

    @pytest.fixture(scope="session", autouse=True)
    def reserve_fixture(self, request):
        """Performs testbed reservation and yields testbed config (``tb_config``)"""
        # in case we do not have config_name we need to find a free testbed from tb_pool_name
        if not self.config_name:
            self.tb_config = self._find_free_testbed_from_the_pool(request)
        else:
            if not self.tb_config:
                self.tb_config = config.load_tb_config(self.config_name, skip_deployment=True, skip_capabilities=True)
        kwargs = {"config": self.tb_config}
        self.res = ReserveLib(**kwargs)
        self._reserve()
        yield
        self._unreserve()
        LogCatcher.attach_to_allure([[log_catcher.get_logger()]])

    def reserve_testbed(self):
        if not self.tb_config:
            self.tb_config = config.load_tb_config(self.config_name, skip_deployment=True, skip_capabilities=True)
        kwargs = {"config": self.tb_config}
        self.res = ReserveLib(**kwargs)
        self._reserve()

    def un_reserve_testbed(self):
        self._unreserve()

    def _find_free_testbed_from_the_pool(self, request):
        tb_pools_file_path = os.path.join(BASE_DIR, "config", "locations", "_testbed_pools.yaml")
        with open(tb_pools_file_path, "r") as tb_pools_file:
            tb_pools = yaml.load(tb_pools_file, Loader=config.YamlLoader)
            if self.tb_pool_name not in tb_pools:
                raise Exception(f"{self.tb_pool_name} does not exist in {tb_pools_file_path}")
        i = 0
        err_cnt = {}
        test_bed = None
        timeout = time.time() + 6 * 60 * 60  # 6 hours should be enough
        while time.time() < timeout:
            if not tb_pools[self.tb_pool_name]:
                raise Exception("There is no testbed in the pool, which we can reserve")
            que = queue.Queue()
            threads_list = []
            for tb_name in tb_pools[self.tb_pool_name]:
                tb_config = config.load_tb_config(tb_name, skip_deployment=True)
                kwargs = {"config": tb_config}
                self.res = ReserveLib(**kwargs)
                log.info(f"Adding command -> {self.res.get_reservation_status(False)} to main thread queue")
                t = threading.Thread(target=lambda q: q.put(self.res.get_reservation_status(False)), args=(que,))
                t.start()
                threads_list.append(t)

            # Join all the threads
            for t in threads_list:
                t.join()

            while not que.empty():
                result = que.get()
                if result["owner"] == "CANNOT GET RESERVATION":
                    # cannot get reservation
                    if err_cnt.get(result["name"]):
                        err_cnt[result["name"]] += 1
                    else:
                        err_cnt[result["name"]] = 1
                    if err_cnt.get(result["name"], 0) >= 3:
                        log.warning(f"Cannot get reservation for '{result['name']}', removing from the testbed pool")
                        tb_pools[self.tb_pool_name].remove(result["name"])
                    continue
                if result["busy"] and not result["busyByMe"]:
                    # tb is busy
                    continue
                # yes, we have free testbed
                test_bed = result["name"]
                break
            if test_bed:
                break
            if not i % 5:
                log.info(f"Cannot get any free testbed in the '{self.tb_pool_name}' testbed pool, waiting...")
            time.sleep(30)
            i += 1
        else:
            raise Exception(f"Cannot find any free testbed in the '{self.tb_pool_name}' testbed pool")

        # once we have it we need to load its tb_config
        cfg = config.load_tb_config(test_bed)
        request.config.option.tb_config = cfg
        for item in request.session.items:
            # better use tb_config fixture if possible, instead of these patched test classes
            if item.cls is not None:
                item.cls.tb_config = cfg
                item.cls.tb_config_orig = cfg
        return cfg

    def _reserve(self):
        if self.skip_reservation:
            log.info("Skipping reservation according to pytest arguments")
            return
        if not self.res.check_reservation_possible():
            return
        timeout = time.time() + 10 * 60 * 60  # 10 hours should be enough
        i = 0
        err_cnt = 0
        while time.time() < timeout:
            status = self.res.get_reservation_status(tool=False)
            log_catcher.process_caller(inspect.stack()[1][3], status)
            if status["owner"] == "CANNOT GET RESERVATION":
                err_cnt += 1
                if err_cnt < 20:
                    log.warning("Cannot check reservation, trying again in 10 sec...")
                    time.sleep(10)
                    continue
                log.warning(
                    f'End up with checking reservation for {status.get("name")}, '
                    f"make sure ssh_gateway is set in the config"
                )
                return
            if status["busy"] and not status["busyByMe"]:
                if not i % 5:
                    log.info(f"Testbed is reserved by {status['owner']}, waiting...")
                time.sleep(30)
            else:
                break
            # reset error counter, only 3 failures in a row can skip reservation
            err_cnt = 0
            i += 1
        else:
            assert False, "Testbed still reserved!"

        self.reserve_t = threading.Thread(target=self._reserve_test_bed, name="tb_reservation_thread")
        self.reserve_t.start()
        log.info(f'Reserving test bed: {status.get("name")}\n')

    def _reserve_test_bed(self):
        i = 0
        while True:
            with lock:
                if cmd := reserve_main_q.pop(self.config_name, None):
                    log.info(f"Stopping main reservation thread for: {self.config_name}")
                    if cmd == "STOP":
                        # Leave it reserved for three minutes, so we will have a top priority with next reservation
                        self.res.reserve_test_bed(3)
                        break
            # reserve every two minutes, but reserve_main_q check every 0.1 sec
            if i % 1200 == 0:
                self.res.reserve_test_bed(10)
                i = 0
            time.sleep(0.1)
            i += 1

    def _unreserve(self):
        if self.skip_reservation:
            return
        if self.reserve_t and self.reserve_t.is_alive():
            log.info(f"Releasing {self.config_name} test bed\n")
            with lock:
                reserve_main_q[self.config_name] = "STOP"
            self.reserve_t.join()
            log.info(
                f'Reservation thread -> "{self.reserve_t.getName()}" current state == '
                f'{"alive" if self.reserve_t.is_alive() else "dead"}'
            )


class ReserveLibLogCatcher(LogCatcher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ts_gen = ReserveLibLogCatcher.gen_utc_ts

    @staticmethod
    def gen_utc_ts():
        return datetime.datetime.now(datetime.timezone.utc).strftime("%m-%d_%H:%M:%S") + " UTC"

    def add(self, log_json, ssh_log=False):
        indent_str = f'\n{" ":2} - '
        if ssh_log:
            # text processing from JSON log_msg body prior to sending to allure
            # consider adding debug level stdout
            msg_str = f'[{log_json["timestamp"]}]: Remote SSH call to server -> {log_json["remote_host"]}\n'
            msg_str += "-" * (len(msg_str) - 1)
            msg_str += f'{indent_str}Caller function: "{log_json["function_name"]}"'
            msg_str += f'{indent_str}Remote command: "{log_json["remote_command"]}"'
            msg_str += f"{indent_str}Output: "
            if log_json["cmd_out"]["truncated"] and type(log_json["cmd_out"]["remote_output"]) == list:
                msg_str += f'(truncated)\n{" ":4} - ' + f'\n{" ":4} - '.join(log_json["cmd_out"]["remote_output"])
                del log_json["cmd_out"]["remote_output"]
            msg_str += log_json["cmd_out"]["remote_output"] if "remote_output" in log_json["cmd_out"] else ""
        else:
            # create msg_str from internal function or thread calls
            # messages handled from `process_caller`
            msg_str = f'[{log_json["timestamp"]}]: Internal function call -> {log_json["function_name"]}\n'
            msg_str += "-" * (len(msg_str) - 1)
            msg_str += f'{indent_str}Caller function: "{log_json["calling_function_name"]}"'
            msg_str += f'{indent_str}Return value => "{log_json["output"]}"'
        msg_str += "\n"
        self.add_to_logs(msg_str)

    def process_caller(self, caller_name, proc_msg):
        # minimal stdout for internal function calls and thread activity
        # pre-process data and send to self.add as JSON blob
        timestamp = self.ts_gen()
        caller = inspect.stack()[1][3]
        if caller == "reserve_test_bed":
            expected_rsrv_keys = ["name", "busy", "busyByMe", "owner", "since", "expiration"]
            expected_msg_vals = all([key in proc_msg.keys() for key in expected_rsrv_keys])
            try:
                proc_msg = str(proc_msg)
            except Exception as e:
                proc_msg = f"<failed-to-parse-reservation-msg>: {e}"
            self.add(
                {
                    "function_name": caller,
                    "calling_function_name": caller_name,
                    "timestamp": timestamp,
                    "output": str(proc_msg),
                    "msg_expct_bool": expected_msg_vals,
                }
            )
        else:
            # proceed with conditionality - if further internal functions need log output
            pass

    def ssh_caller(self, remote_host, caller_name, command, output):
        # minimal stdout for ssh calls to RPI server
        # pre-process data and send to self.add as JSON blob
        timestamp = self.ts_gen()
        output_dict = {"remote_output": output, "truncated": False}
        if command.startswith('echo "$(tail -2000') and "\n" in output:
            # truncate reservation log to last 4 lines - i.e. 4 most recent reservations
            truncated_out = output_dict["remote_output"].split("\n")[-4:]
            output_dict.update({"remote_output": truncated_out, "truncated": True})
        self.add(
            {
                "function_name": caller_name,
                "remote_host": remote_host,
                "remote_command": command,
                "cmd_out": output_dict,
                "timestamp": timestamp,
            },
            ssh_log=True,
        )


log_catcher = ReserveLibLogCatcher(default_name="log_reservelib")
