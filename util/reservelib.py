import os
import getpass
import subprocess
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
import logging

from packaging.version import Version

from lib_testbed.generic.util.logger import log, LogCatcher
from lib_testbed.generic.util.common import BASE_DIR, CACHE_DIR, skip_exception
from lib_testbed.generic.util import config
from lib_testbed.generic.client.client import Clients

SSH_GATEWAY = "ssh_gateway"
RESERVELIB_OUT_FILE = "log_reservelib"

__version__ = "3.4.1"
"""Reservelib version."""

# Reservelib version history:
# * 3.4.1: Updated pytest plugin log to see which testbed is being used by someone else.
# * 3.4.0: Updated unreserve response: displaying "TESTBED WAS NOT RESERVED" when trying to free an unused testbed.
#   Also, replaced deprecated :py:class:`distutils.version.StrictVersion` with :py:class:`packaging.version.Version`.
# * 3.3.0: Now timestamps can all be retuned in UTC time zone, skipping timezone conversion based on the
#   skip_tz_conversion constructor argument. Also fixed a small bug - force-free message was not stored in
#   the message column, but in timestamp with parenthesis resulting with incorrect processing of that message.
# * 3.2.1: logging exceptions in getting history on debug level, as users report being overwhelmed with logs.
# * 3.2.0: now updating local reservation file (the counter) at the end of pytest run.
#   reservation getter does not update the file format, added a dedicated method to update reservation file format.
#   added a method checking if newer version is available (based on the current reservation file).
#   Now reservation row includes reservation message as the last element of the reservation row:
#   "<hostname_or_job>[-<build_number>]:::<machine_uuid>:::<start_time>:::<end_time>:::<reservelib-version>
#   :::<is_forced flag>:::<reservation_message>"
#   The commands return a dictionary with the information about team responsible, and whether the operation was forced.
#   Added a method checking if the file format is not outdated, so that the tool can invoke it and present the
#   command to fix the file to the users.
#   In case pytest runs into an outdated file format, we convert it to the modern format without bothering the users.
#   Increased default maximum reservation file from 3 to 7 days.
# * 3.1.1: replace "tail | tee" call with "echo > reservation" - as the behavior was undefined. Also made sure that
#   the exipry date does not contain reservation message.
# * 3.1.0: now clearing reservation file leaves out the information about the user who cleared it.
# * 3.0.0: changed value separator from __ (double underscore) to ::: (tripple colon)
#   The reservation file is updated reserve on get operation, and should prevent old tool versions from working.
# * 2.0.0: add handling for additional/extra values in every reservation: reservelib version and force-flag
# * 1.0.0: legacy versionlib, stores reservation row on OSRT server:
#   In 1.0, reservation row contains:
#   <hostname_or_job>[-<build_number>]__<machine_uuid>__<start_time>__<end_time> <reservation_message>
#   with reservation message being optional.


class ReserveLib:
    def __init__(self, **kwargs):
        self.tb_config = kwargs.get("config")
        self.json_output = kwargs.get("json", False)
        self.new_reservation_msg = self.tb_config.get("message", "")
        self.skip_tz_conversion = kwargs.get("skip_tz_conversion", False)
        self.tb_name = config.get_location_name(self.tb_config)
        self.res_file = f"/.reserve_{self.tb_name}"
        self.client_lib = self._get_client_lib()
        self.sudo = "sudo " if kwargs.get("sudo", True) else ""  # if False, the commands will run without sudo
        self.ensure_res_file_cmd = f"{self.sudo}touch {self.res_file}; "
        if not (host_name := os.environ.get("CUSTOM_HOSTNAME")):
            host_name = os.uname()[1]

        if host_name.endswith("-docker"):
            host_name = host_name[: -len("-docker")]  # strip '-docker' from the end of the hostname
        self.host_name = host_name
        self.machine_uuid = self._get_machine_uuid()
        self.log_catcher = log_catcher  # reference to log_catcher, allows derived classes to log into their own loggers
        self.team_responsible = self.tb_config.get("reservation", {}).get("team_responsible", "-")
        self.max_reserv_time = self.tb_config.get("reservation", {}).get("max_reservation_time", 7 * 24 * 60)

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
        DEPRECATED!
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
        log.debug("Server SSH command '%s' returned %s", command, ret)
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
            log.debug("Getting current reservation message")
            file_operation_cmds = f'flock -x {self.res_file} --command "tail -1 {self.res_file} && sync"'
            cmd = self.ensure_res_file_cmd + file_operation_cmds

            out = self._server_ssh_call(cmd)
        except Exception as error:
            log.error(f"Failed to parse reservation log -> {error}")
            out = ""
        if ":::" in out:
            info = out.split(":::")
            message_raw = info[3].split() if len(info) > 3 else []
            if len(message_raw) > 1:
                message = " ".join(message_raw[1:]).replace("(", "").replace(")", "")
        log.debug("Current reservation message: '%s'", message)
        return message

    @skip_exception(Exception, reraise=True)
    @_tb_purpose_decorator
    def reserve_test_bed(self, timeout=120, by_pytest_plugin=False):
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
                "message": "-",
                "team_responsible": self.team_responsible,
                "version": __version__,
                "is_forced": self.tb_config.get("force", False),
            }
        if not isinstance(timeout, int):
            timeout = int(timeout)
        status = self.get_reservation_status(tool=False)
        self.log_catcher.process_caller(inspect.stack()[1][3], status)
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
                    "message": "-",
                    "team_responsible": self.team_responsible,
                    "version": __version__,
                    "is_forced": self.tb_config.get("force", False),
                }

        # limit the file to 2000 lines
        # this is the most problematic part, which often corrupts reservation file, so do it before adding new line
        file_operation_cmds = (
            f"flock -x {self.res_file} --command 'echo \"$(tail -2000 {self.res_file})\" > {self.res_file} && sync'"
        )
        cmd = self.ensure_res_file_cmd + file_operation_cmds
        self._server_ssh_call(cmd)

        # TODO: in case of force, previous reservation should end and new start
        res_row = self.generate_reservation_row(status, timeout, by_pytest_plugin=by_pytest_plugin)
        # in case tb is reserved by Me, just update last row -> so delete it first
        # but also don't erase last cleared-history operation:
        if status["busyByMe"] and status.get("message") != "cleared-history":
            file_operation_cmds = (
                f'flock -x {self.res_file} --command \'{self.sudo}sed -i "$ d" {self.res_file} && '
                f'echo "{res_row}" | {self.sudo}tee -a {self.res_file} && sync\''
            )
        else:
            file_operation_cmds = (
                f"flock -x {self.res_file} --command 'echo \"{res_row}\" | {self.sudo}tee -a {self.res_file} && sync'"
            )

        cmd = self.ensure_res_file_cmd + file_operation_cmds
        out = self._server_ssh_call(cmd)
        if out.startswith("Error:"):
            return {
                "name": self.tb_name,
                "status": False,
                "owner": "ERROR: CANNOT RESERVE",
                "since": status["since"],
                "expiration": "-",
                "message": "-",
                "team_responsible": self.team_responsible,
                "version": __version__,
                "is_forced": self.tb_config.get("force", False),
            }

        res_row = res_row.split(":::")
        # remove msg from res_row[3] - if msg exists -> this convoluted mechanism is DEPRECATED,
        # it is to be removed in the future!
        if len(res_row[3].split()) > 1:
            res_row[3], *self.new_reservation_msg = res_row[3].split()
            self.new_reservation_msg = " ".join(self.new_reservation_msg).replace("(", "").replace(")", "")
        rsrv_dict = {
            "name": self.tb_name,
            "status": True,
            "owner": res_row[0],
            "since": f"{self._convert_utc_to_local(res_row[2])}",
            "expiration": f"{self._convert_utc_to_local(res_row[3].split()[0])}",
            "message": self.new_reservation_msg,
            "team_responsible": self.team_responsible,
            "version": __version__,
            "is_forced": self.tb_config.get("force", False),
        }
        return rsrv_dict

    @skip_exception(Exception, reraise=True)
    @_existing_msg_decorator
    @_tb_purpose_decorator
    def get_reservation_status(self, tool=True):
        """
        Check reservation status
        """
        log.debug("Getting reservation status")
        if not self.check_reservation_possible():
            return {
                "name": self.tb_name,
                "busy": False,
                "busyByMe": False,
                "owner": "CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
                "is_forced": False,
                "team_responsible": self.team_responsible,
                "message": "-",
            }
        file_operation_cmds = f'flock -x {self.res_file} --command "tail -1 {self.res_file}"'

        cmd = self.ensure_res_file_cmd + file_operation_cmds

        out = self._server_ssh_call(cmd)

        if not out:
            file_operation_cmds = f'flock -x {self.res_file} "tail -1 {self.res_file}" || echo empty file'
            cmd = self.ensure_res_file_cmd + file_operation_cmds

            out = self._server_ssh_call(cmd)
            if out != "empty file":
                return {
                    "name": self.tb_name,
                    "busy": True,
                    "busyByMe": False,
                    "owner": "CANNOT GET RESERVATION",
                    "since": "-",
                    "expiration": "-",
                    "version": "Unknown",
                    "is_forced": False,
                    "team_responsible": self.team_responsible,
                    "message": "-",
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
                "version": "Unknown",
                "is_forced": False,
                "team_responsible": self.team_responsible,
                "message": "-",
            }
        # analyze other exceptions
        if out.startswith("Error:") or ":::" not in out:
            return {
                "name": self.tb_name,
                "busy": True,
                "busyByMe": False,
                "owner": "CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
                "version": "Unknown",
                "is_forced": False,
                "team_responsible": self.team_responsible,
                "message": "-",
            }
        # analyze the last row of reservation file
        info = out.split(":::")
        # gather existing reservation message, if it exists - split apart timestamp from initial part of line
        try:
            if len(info[3].split()) > 1:
                info[3] = info[3].split()[0]
            if "+" not in info[3]:
                log.debug("Extending timestamp with +00:00 timezone information")
                info[3] += "+00:00"
            busy = datetime.datetime.now(tz=datetime.UTC) < datetime.datetime.fromisoformat(info[3])
        except (ValueError, IndexError) as error:
            busy = None
            log.error("Invalid timestamp in reservation file -> %s", error)
        if len(info) < 4 or busy is None:
            log.error("Reservation file is corrupted.")
            return {
                "name": self.tb_name,
                "busy": True,
                "busyByMe": False,
                "owner": "CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
                "version": "Unknown",
                "is_forced": False,
                "team_responsible": self.team_responsible,
                "message": "-",
            }
        busy_by_me = busy and self._get_machine_uuid() == info[1]
        # nicer look of the date
        if tool:
            info[2] = self._convert_utc_to_local(info[2])
            info[3] = self._convert_utc_to_local(info[3])
        try:
            version = info[4]
        except IndexError:
            log.debug("Could not determine reservelib version")
            version = "Unknown"
        try:
            is_forced = info[5] == "True"
        except IndexError:
            log.debug("Could not determine if resrvation was forced (assuming False)")
            is_forced = False
        try:
            message = info[6]
        except IndexError:
            message = ""
        if busy:
            return {
                "name": self.tb_name,
                "busy": busy,
                "busyByMe": busy_by_me,
                "owner": info[0],
                "since": f"{info[2]}",
                "expiration": f"{info[3]}",
                "version": version,
                "is_forced": is_forced,
                "team_responsible": self.team_responsible,
                "message": message,
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
                "version": version,
                "is_forced": is_forced,
                "team_responsible": self.team_responsible,
                "message": message,
            }

    def update_old_reservation_format(self):
        """Update the file format to the latest reservation format.

        Updates separator string. Old format was using __ [double underscore] as a separator, new file format
        uses ::: [triple colon].
        """
        convert_cmd = f"flock -x {self.res_file} --command \"{self.sudo}sed -i -e 's/__/:::/g' {self.res_file}\""
        output = self._server_ssh_call(convert_cmd)
        log.info("Reservation file conversion resulted: %s", output)
        return {"name": self.tb_name, "status": True if "Error" not in output else False, "message": "-"}

    @skip_exception(Exception, reraise=True)
    def unreserve(self, by_pytest_plugin=False):
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
                "version": "Unknown",
                "is_forced": False,
                "team_responsible": self.team_responsible,
                "message": "-",
            }
        status = self.get_reservation_status(tool=False)
        self.log_catcher.process_caller(inspect.stack()[1][3], status)
        # if script cannot get reservation notify about that
        if status["owner"] == "CANNOT GET RESERVATION":
            return {
                "name": self.tb_name,
                "status": False,
                "owner": "ERROR: CANNOT GET RESERVATION",
                "since": "-",
                "expiration": "-",
                "version": status.get("version"),
                "is_forced": status.get("is_forced"),
                "team_responsible": self.team_responsible,
                "message": "-",
            }

        # if not reserved just exit
        if not status["busy"]:
            return {
                "name": self.tb_name,
                "status": True,
                "owner": "TESTBED WAS NOT RESERVED",
                "since": "-",
                "expiration": "-",
                "message": "-",
            }

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
                    "version": status.get("version"),
                    "is_forced": status.get("is_forced"),
                    "team_responsible": self.team_responsible,
                    "message": status.get("message", ""),
                }

        # in case of force, we need to keep owner, but also is_forced flag that's set only when getting reservation
        res_row = self.generate_reservation_row(status, 0, keep_owner=True, by_pytest_plugin=by_pytest_plugin)
        log.debug("Unreserve force-status -> should not be changed")
        row = res_row.split(":::")
        row[5] = str(status["is_forced"])
        res_row = ":::".join(row)
        log.debug("Unreserve reservation row: %s", res_row)
        if self.tb_config.get("force"):
            # we do force-free, so we want to keep the is_forced flag of the reservation and
            # add a 1-second long reservation to indicate that it was force-freed
            previous_end = row[3].split()[0]
            row[2], row[3] = (
                datetime.datetime.fromisoformat(previous_end).isoformat(),
                (datetime.datetime.fromisoformat(previous_end) + datetime.timedelta(seconds=1)).isoformat(),
            )
            row[5] = "True"
            row[6] = "forced-free"
            res_row += "\n" + ":::".join(row)
            log.debug("Will be storing the information about force-free with 2 rows:\n%s", res_row)

        file_operation_cmds = (
            f'flock -x {self.res_file} --command \'{self.sudo}sed -i "$ d" {self.res_file} && '
            f'echo -e "{res_row}" | {self.sudo}tee -a {self.res_file} && sync\''
        )
        cmd = self.ensure_res_file_cmd + file_operation_cmds
        out = self._server_ssh_call(cmd)

        if out.startswith("Error:"):
            return {
                "name": self.tb_name,
                "status": False,
                "owner": "ERROR: CANNOT UNRESERVE",
                "since": status["since"],
                "expiration": "-",
                "version": "Unknown",
                "is_forced": False,
                "team_responsible": self.team_responsible,
                "message": "-",
            }
        res_row = res_row.split(":::")
        try:
            version = res_row[4]
        except IndexError:
            log.debug("Could not determine reservelib version")
            version = "Unknown"
        try:
            is_forced = res_row[5] == "True"
        except IndexError:
            log.debug("Could not determine if resrvation was forced (assuming False)")
            is_forced = False
        try:
            message = res_row[6]
        except IndexError:
            message = ""
        return {
            "name": self.tb_name,
            "status": True,
            "owner": "-",
            "since": f"{self._convert_utc_to_local(res_row[2])}",
            "expiration": f"{self._convert_utc_to_local(res_row[3].split()[0])}",
            "version": version,
            "is_forced": is_forced,
            "team_responsible": self.team_responsible,
            "message": message,
        }

    def clear_reservation_history(self):
        """Clear reservation history (remove history from reservation file)."""
        if not self.check_reservation_possible():
            return {"name": self.tb_name, "status": False, "msg": "RESERVATION NOT POSSIBLE"}
        status = self.get_reservation_status(tool=False)
        self.log_catcher.process_caller(inspect.stack()[1][3], status)
        # if reserved, keep the last line
        res_row = self.generate_reservation_row(status, 1)
        row = res_row.split(":::")
        log.debug("Unreserve reservation row: %s", res_row)
        previous_end = row[3].split()[0]
        row[2], row[3] = (
            datetime.datetime.fromisoformat(previous_end).isoformat(),
            (datetime.datetime.fromisoformat(previous_end) + datetime.timedelta(seconds=1)).isoformat(),
        )
        row[6] = "cleared-history"
        res_row = ":::".join(row)
        log.debug("Will be storing the information about history-clear:\n%s", res_row)
        if status["busy"]:
            # when testbed is busy, we clear history but leave out the information about the current reservation
            file_operation_cmds = (
                f"flock -x {self.res_file} --command "
                f"\"echo -e '{res_row}\n$(tail -1 {self.res_file})' | {self.sudo}tee {self.res_file} && sync\""
            )
            cmd = self.ensure_res_file_cmd + file_operation_cmds

            out = self._server_ssh_call(cmd)
        else:
            out = self._server_ssh_call(f"{self.sudo}rm {self.res_file}; sync")

            file_operation_cmds = (
                f"flock -x {self.res_file} --command 'echo \"{res_row}\" | {self.sudo}tee -a {self.res_file} && sync'"
            )
            cmd = self.ensure_res_file_cmd + file_operation_cmds

            out += self._server_ssh_call(cmd)

        if "Error" in out:
            return {"name": self.tb_name, "status": False, "message": "CLEARING ERROR"}
        else:
            return {"name": self.tb_name, "status": True, "message": "DONE"}

    def usage_statistics(self, time_res="week", min_use="0"):  # noqa: C901
        """
        Get test bed usage statistics; time_res=week|month|year
        """
        assert time_res in ["day", "week", "month", "year"]
        assert min_use.isdigit()
        min_use = int(min_use)
        ret = {"name": self.tb_name}
        if min_use:
            ret["in_use"] = "-"
        if not self.check_reservation_possible():
            ret["stats"] = "RESERVATION NOT POSSIBLE"
            return ret
        if time_res == "day":
            delta = 1
        elif time_res == "week":
            delta = 7
        elif time_res == "month":
            delta = 30
        else:
            delta = 365

        file_operation_cmds = f'flock -x {self.res_file} --command "cat {self.res_file}"'
        cmd = self.ensure_res_file_cmd + file_operation_cmds

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

        boundary = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=delta)
        res_count = 0
        res_time = 0
        for line in out.split("\n")[::-1]:
            log.info(line)
            reservation = line.split(":::")
            if len(reservation) < 4:
                if line:  # report it, unless it's just an empty line
                    log.warning(f'Invalid reservation line for {self.tb_name}: "{line}"')
                continue
            st_timestamp = reservation[2]
            if "+" not in st_timestamp:
                log.debug("Extending timestamp with +00:00 timezone information")
                st_timestamp += "+00:00"
            st_res = datetime.datetime.fromisoformat(st_timestamp)
            # split handles reservation messages
            end_timestamp = reservation[3].split()[0]
            if "+" not in end_timestamp:
                log.debug("Extending timestamp with +00:00 timezone information")
                end_timestamp += "+00:00"
            end_res = datetime.datetime.fromisoformat(end_timestamp)
            if end_res < boundary:
                # latest reservation is earlier than boundary, so there is nothing to analyze above
                break
            res_count += 1
            # if reservation started before boundary, use boundary as reservation starting point
            if st_res < boundary:
                st_res = boundary
            # if reservation ends after current time, stop NOW
            if end_res > datetime.datetime.now(datetime.UTC):
                end_res = datetime.datetime.now(datetime.UTC)
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

    def check_outdated_reserve_format(self) -> bool:
        """Returns True when the file format is outdated."""
        file_operation_cmds = f'flock -x {self.res_file} --command "cat {self.res_file}"'
        cmd = self.ensure_res_file_cmd + file_operation_cmds

        out = self._server_ssh_call(cmd)
        return "__" in out

    @skip_exception(Exception, reraise=True)
    def generate_reservation_row(
        self,
        current_reservation: dict,
        reservation_time: int = 120,
        keep_owner: bool = False,
        by_pytest_plugin: bool = False,
    ):
        """
        Generate reservation file name
        Args:
            current_reservation: current reservation
            reservation_time:  timeout for test bed reservation
            keep_owner: return the same owner (needed in case of force)
            by_pytest_plugin: indicates whether the reservation was called by pytest reservation plugin.

        Returns: (str) reservation file row:
            "<hostname_or_job>[-<build_number>]:::<machine_uuid>:::<start_time>:::<end_time> <reservation_message>
            :::<reservelib_version>:::<is_forced>"

        """
        if keep_owner:
            file_operation_cmds = f'flock -x {self.res_file} --command "tail -1 {self.res_file}"'
            cmd = self.ensure_res_file_cmd + file_operation_cmds

            out = self._server_ssh_call(cmd)
            assert out and "Error" not in out
            out = out.split(":::")
            owner = out[0]
            mach_uuid = out[1]
        elif os.environ.get("JOB_NAME"):
            build_number = f"-{os.environ.get('BUILD_NUMBER')}" if os.environ.get("BUILD_NUMBER") else ""
            job_name = os.environ.get("JOB_NAME")
            owner = f"{job_name}{build_number}"
            if not self.new_reservation_msg:
                if build_number:
                    # we have both job_name and build_number -- we were most probably started by Jenkins
                    self.new_reservation_msg = f"Jenkins job on {self.host_name}"
                else:
                    # just job_name, possibly exported by a user -- use a more generic "<job_name> on <host>"
                    self.new_reservation_msg = f"{job_name} on {self.host_name}"
            mach_uuid = self.machine_uuid
        else:
            build_number = f"-{os.environ.get('BUILD_NUMBER')}" if os.environ.get("BUILD_NUMBER") else ""
            try:
                user_name = getpass.getuser()
                owner = f"{user_name}@{self.host_name}{build_number}"
            except Exception:
                owner = f"{self.host_name}{build_number}"
            mach_uuid = self.machine_uuid

        if current_reservation["owner"] == owner:
            # we should get here only if extending reservation by the same user, otherwise create new row with new owner
            start_time = current_reservation.get("since")
        else:
            start_time = datetime.datetime.now(datetime.UTC).isoformat()

        end_time = current_reservation.get("expiration").split()[0]
        if end_time == "-":
            end_time = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=reservation_time)
        else:
            end_time = datetime.datetime.fromisoformat(end_time)
            if not (
                by_pytest_plugin and datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10) < end_time
            ):
                end_time = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=reservation_time)

        rsrv_msg = str(self.new_reservation_msg) if self.new_reservation_msg else ""
        owner = self.tb_config["owner"] if self.tb_config.get("owner") else owner
        reservation_row = (
            f"{owner}:::{mach_uuid}:::{start_time}:::{end_time.isoformat()}"
            f":::{__version__}:::{self.tb_config.get('force', False)}:::{rsrv_msg}"
        )
        log.debug("Prepared reservation row: %s", reservation_row)
        return reservation_row

    @skip_exception(Exception, reraise=True, log_level=logging.DEBUG)
    def get_history(self, days: int = 0) -> list[dict]:
        """Returns a list with reservation status (reservation history) for the current testbed."""
        time_limit = None
        if days == 0:
            log.debug("Getting full reservation history")
        else:
            log.debug("Getting history for last %s days", days)
            time_limit = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
        cmd = f'flock -x {self.res_file} --command "cat {self.res_file}"'
        out = self._server_ssh_call(cmd)
        if "Error" in out:
            log.error("Ran into an error: %s", out)
            raise IOError(f"Could not process reservation history for {self.tb_name}")
        history = []
        for line in out.splitlines():
            row = line.split(":::")
            # split handles OLD reservation messages
            end_msg = row[3].split()
            expiration = end_msg[0]
            if len(end_msg) > 1:
                message = " ".join(end_msg[1:]).replace("(", "").replace(")", "")
            else:
                message = "-"
            try:
                version = row[4]
            except IndexError:
                log.debug("Could not determine reservelib version")
                version = "Unknown"
            try:
                is_forced = row[5] == "True"
            except IndexError:
                log.debug("Could not determine if resrvation was forced (assuming False)")
                is_forced = False
            try:
                message = row[6]
            except IndexError:
                log.debug("Could not determine reservation message (old version of reservelib was used!)")

            end_date_tz = "" if "+" in expiration or "Z" in expiration else "+00:00"
            end_date = datetime.datetime.fromisoformat(f"{expiration}{end_date_tz}")
            if time_limit and end_date < time_limit:
                continue

            history.append(
                {
                    "name": self.tb_name,
                    "owner": row[0],
                    "since": f"{self._convert_utc_to_local(row[2])}",
                    "expiration": f"{self._convert_utc_to_local(expiration)}",
                    "message": message,
                    "version": version,
                    "is_forced": is_forced,
                    "team_responsible": self.team_responsible,
                }
            )

        return history

    def get_latest_stable_reservation_used(self) -> Version:
        """Parse version history, get the newest version of reservelib used to reserve the testbed - as parsed
        from reservation row. The parser intentionally skips parsing pre-releases (alpha/beta/dev/rc)."""
        history = self.get_history()
        newest_ver = Version("0.0.0")
        for row in history:
            str_ver = row.get("version")
            if str_ver:
                try:
                    ver = Version(str_ver)
                    if ver.pre:
                        continue
                    if ver > newest_ver:
                        newest_ver = ver
                except ValueError:
                    pass  # happens for some pre-releases or unparseable, do nothing
        return newest_ver

    def is_newer_available(self):
        """Returns True when parsing the file suggests that a newer version of reservelib is available."""
        try:
            return self.get_latest_stable_reservation_used() > Version(__version__)
        except ValueError:
            return False

    def _get_machine_uuid(self):
        """
        Generate unique machine UUID
        Returns: (str) machine uuid
        """
        if self.tb_config.get("owner"):
            return self.tb_config["owner"]
        else:
            return (
                f"{self.host_name}{str(uuid.UUID(int=uuid.getnode())).split('-')[-1]}"
                f"{os.environ.get('BUILD_NUMBER', '')}"
            )

    def _convert_utc_to_local(self, utc_time):
        """
        Converts utc time to local
        Args:
            utc_time: (str) timestamp in ISO format

        Returns: (str)

        """
        utc_time = datetime.datetime.fromisoformat(utc_time)
        if self.skip_tz_conversion:
            return datetime.datetime.strftime(utc_time, "%Y-%m-%d %H:%M:%S")
        offset = datetime.datetime.now(datetime.UTC).astimezone().utcoffset()
        log.debug("UTC offset: %s", offset)
        return datetime.datetime.strftime(utc_time + offset, "%Y-%m-%d %H:%M:%S")


# keeping that global, so other plugins can stop the reservation threat, e.g PyUpgradePlugin
reserve_main_q = {}
lock = threading.RLock()


class PyReservePlugin:
    def __init__(self, config_name, tb_pool_name, skip_reservation, tb_config=None):
        assert config_name or tb_pool_name, "Cannot be used without config file or testbed pool name"
        self.config_name = config_name
        self.tb_pool_name = tb_pool_name
        self.skip_reservation = skip_reservation
        self.reserve_t = None
        self.res = None
        self.tb_config = tb_config
        self.log_catcher = log_catcher  # reference to log_catcher, allows derived classes to log into their own loggers
        self.busy_by_me = False  # hold the information whether the testbed is busy by me

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
        LogCatcher.attach_to_allure([[self.log_catcher.get_logger()]])

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
        if self.res.check_outdated_reserve_format():
            self.res.update_old_reservation_format()
        if not self.res.check_reservation_possible():
            return
        timeout = time.time() + 10 * 60 * 60  # 10 hours should be enough
        i = 0
        while time.time() < timeout:
            status = self.res.get_reservation_status(tool=False)
            self.log_catcher.process_caller(inspect.stack()[1][3], status)
            if status["owner"] == "CANNOT GET RESERVATION":
                log.warning("Cannot check reservation, trying again in 10 sec...")
                time.sleep(30)
                continue
            if status["busy"] and not status["busyByMe"]:
                if not i % 5:
                    log.info("Testbed %s is reserved by %s, waiting...", status["name"], status["owner"])
                time.sleep(30)
            else:
                break
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
                        res_result = self.res.reserve_test_bed(3, by_pytest_plugin=True)
                        local_res_file = f"{CACHE_DIR}/.reserve_{res_result.get('name')}"
                        if res_result.get("status") and os.path.exists(local_res_file):
                            log.info(
                                "Updating local reservation file %s with new expiry date: %s",
                                local_res_file,
                                res_result.get("expiration"),
                            )
                            subprocess.run(
                                f"flock -x {local_res_file} echo \"{res_result['expiration']}\" > {local_res_file}",
                                shell=True,
                            )
                        break
            # reserve every two minutes, but reserve_main_q check every 0.1 sec
            if i % 1200 == 0:
                reservation_result = self.res.reserve_test_bed(10, by_pytest_plugin=True)
                with lock:
                    self.busy_by_me = reservation_result.get("status") is True

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
                'Reservation thread -> "%s" current state == "%s"',
                self.reserve_t.name,
                "alive" if self.reserve_t.is_alive() else "dead",
            )

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_call(self, item):
        """Before executing the next test function, check if testbed is still busy-by-me.
        This hook should enforce pausing test execution if someone forces-reserve, and the status is only updated
        in the reservation plugin, by the reservation thread.
        """
        # we are checking reservation in this hook, which should be invoked AFTER fixtures are generated,
        # including the reservation fixture. The pytest_runtest_setup fixture might be invoked too early.
        if self.skip_reservation:
            return
        with lock:
            busy_by_me = self.busy_by_me

        if busy_by_me:
            # reserved by the current user/machine, just continuing execution as normal
            return

        counter = 0
        log.error("Looks like testbed got reserved by someone else during test execution, pausing test execution...")
        while not busy_by_me:
            time.sleep(120)
            with lock:
                busy_by_me = self.busy_by_me
            if busy_by_me:
                log.info("Regained testbed reservation")
                return

            counter += 1
            if counter > 180:  # 180 * 2 minutes = 6h
                log.error("Could not get reservation for testbed for more than 6 hours, time to give up")
                pytest.exit(reason="Testbed was force-reserved by someone else during test session.", returncode=1)


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
            if log_json["cmd_out"]["truncated"] and isinstance(log_json["cmd_out"]["remote_output"], list):
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

    def step_collect(self, test_data):
        """Overriden to stop attaching log_reservelib to steps."""
        ...


log_catcher = ReserveLibLogCatcher(default_name="log_reservelib")
