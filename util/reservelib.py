import os
import getpass
import subprocess
import sys
import traceback
import time
import pytest
import uuid
import datetime
import threading
import logging

from packaging.version import Version

from pexpect import pxssh

from lib_testbed.generic.util.pytest_utils import safe_exit_pytest
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import CACHE_DIR, skip_exception
from lib_testbed.generic.util import config
from lib_testbed.generic.client.client import Clients

SSH_GATEWAY = "ssh_gateway"
RESERVELIB_OUT_FILE = "log_reservelib"

__version__ = "4.0.1"
"""Reservelib version."""

# Reservelib version history:
# * 4.0.1: Updated lock_reserve_file context manager to skip strict host key checking and user known hosts file to
#          eliminate ssh connection errors against some testbeds.
# * 4.0.0: Removed the old concept of "reservation message" that was glued onto end timestamp in the reservation file.
#          In the case that such reservation file is parsed, the tool will error. Reservation file needs to be
#          removed and reservations need to be started over.
#          Added a new context manager to safely set and release reservations obtaining a new flock to prevent
#          race conditions setting reservation.
#          Removed unused optional "sudo" command because it was unused.
#          Removed support for testbed pools.
#          Removed the feature of filling out testbed purpose and reservation message as a decorator in favor of
#          explicit values - makes the code easier to read and debug.
#          Removed ReserveLibLogCatcher, as it was unused anyway.
#          Improved logging by moving some messages into trace level.
# * 3.7.1: Updated/cleaned up logging.
# * 3.7.0: Removed methods that were used by the old lab-tool. Safe exiting pytest (or xdist worker) if a testbed
#          cannot be reserved at the session start. This should result with the remaining tests being re-scheduled
#          to other workers as opposed to failing all items scheduled for that testbed. The test currently executed
#          will get the status SKIPPED.
# * 3.6.2: Fixed issue where freeing testbed overwrites original reservation message.
# * 3.6.1: Fixed issue where we copied is_forced field from last reservation even if the reservation already expired.
#          Because of this issue, once you forced a reservation, every subsequent reservation had is_forced set to True.
# * 3.6.0: Exposed new ReserveLib class attribute ``version`` returning an instance of a
#          :py:class`packaging.version.Version` with the current version, for further comparison.
#          Also fixed a bug - the is_forced flag was not retained when extending current reservation that
#          was originally forced.
#          In addition, fixed checking for prerelease by calling :py:attr:`packaging.version.Version.is_prerelease`
#          as opposed to :py:attr:`packaging.version.Version.is_pre`
# * 3.5.1: Fixed broken support for custom owner-id when getting reservation, the custom owner was ignored in the
#   check for existing reservation, the method get_reservation_status.
# * 3.5.0: The bool value of busyByMe is now evaluated based on first 2 columns, index 0 and 1, as opposed to just
#   column 1, so that current user id depends on username and machine id. This change is fully backwards compatible.
# * 3.4.2: Now calling safe_exit_pytest() to make an attempt to close one xdist runner when testbed reservation
#   cannot be regained instead of closing pytest with pytest.exit() call. Fallback to pytest.exit() in case of
#   any error.
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


class lock_reserve_file:
    """Locking mechanism - to be used only when setting or getting reservation.
    The assumption is that the machine under the ssh_gateway is on bash.
    """

    def __init__(self, tb_config, client_lib, res_file):
        self.tb_config, self.client_lib, self.res_file = tb_config, client_lib, res_file
        self.lock_file = f"/tmp/{self.res_file}.lock"
        ssh_gateway = self.tb_config.get("ssh_gateway")
        user, passwd, hostname = ssh_gateway.get("user"), ssh_gateway.get("pass"), ssh_gateway.get("hostname")
        log.debug("Establishing connection to acquire lock file...")
        try:
            self.session = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
            self.session.login(hostname, user, passwd)
            self.ssh_connection_available = True
        except pxssh.ExceptionPxssh:
            log.warning("Could not safely establish connection to host to grab lockfile, continuing")
            self.ssh_connection_available = False
        self.lock_acquired = False

    def __enter__(self):
        if not self.ssh_connection_available:
            return self
        if self.lock_acquired:
            log.debug("Lock already acquired, doing nothing")
            return self
        log.debug("--> Locking reserve file")
        self.session.sendline(f"touch {self.lock_file} && exec {{LOCK_FD}}>{self.lock_file}")
        self.session.prompt()
        self.session.sendline('flock -x "$LOCK_FD"')
        if not self.session.prompt(timeout=15):
            raise RuntimeError("Cloud not acquire reservation lock")
        log.trace("Reservation lock acquired")
        self.lock_acquired = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.ssh_connection_available:
            return
        if self.lock_acquired:
            log.debug("<-- Unlocking reserve file")
            self.session.sendline("exec {LOCK_FD}>&-")
            log.trace("Reservation lock released")
            self.session.close()
            self.lock_acquired = False


class ReserveLib:
    def __init__(self, **kwargs):
        self.tb_config = kwargs.get("config")
        self.json_output = kwargs.get("json", False)
        self.new_reservation_msg = self.tb_config.get("message", "")
        self.skip_tz_conversion = kwargs.get("skip_tz_conversion", False)
        self.tb_name = config.get_location_name(self.tb_config)
        self.res_file = f"/.reserve_{self.tb_name}"
        self.client_lib = self._get_client_lib()
        self.ensure_res_file_cmd = f"sudo touch {self.res_file}; "
        if not (host_name := os.environ.get("CUSTOM_HOSTNAME")):
            host_name = os.uname()[1]

        if host_name.endswith("-docker"):
            host_name = host_name[: -len("-docker")]  # strip '-docker' from the end of the hostname
        self.host_name = host_name
        self.machine_uuid = self._get_machine_uuid()
        self.team_responsible = self.tb_config.get("reservation", {}).get("team_responsible", "-")
        self.max_reserv_time = self.tb_config.get("reservation", {}).get("max_reservation_time", 7 * 24 * 60)

    @property
    def version(self) -> Version:
        """Returns reservelib version."""
        return Version(__version__)

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

    @skip_exception(Exception, reraise=True)
    def reserve_test_bed(self, timeout=120, by_pytest_plugin=False):
        """
        Reserve test bed. Default timeout is 120 minutes
        """
        with lock_reserve_file(self.tb_config, self.client_lib, self.res_file):
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
                    "purpose": self.tb_config.get("purpose", "-"),
                }
            if not isinstance(timeout, int):
                timeout = int(timeout)
            status = self.get_reservation_status(tool=False)
            if not self.tb_config.get("force"):
                # check if we can reserve test bed
                log.debug("Checking if testbed is not reserved")
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
                        "is_forced": self.tb_config.get("force", status.get("is_forced", False)),
                        "purpose": self.tb_config.get("purpose", "-"),
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
                    f'flock -x {self.res_file} --command \'sudo sed -i "$ d" {self.res_file} && '
                    f'echo "{res_row}" | sudo tee -a {self.res_file} && sync\''
                )
            else:
                file_operation_cmds = (
                    f"flock -x {self.res_file} --command 'echo \"{res_row}\" | sudo tee -a {self.res_file} && sync'"
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
                    "is_forced": self.tb_config.get("force", status.get("is_forced", False)),
                    "purpose": self.tb_config.get("purpose", "-"),
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
                "is_forced": self.tb_config.get("force", status.get("is_forced", False)),
                "purpose": self.tb_config.get("purpose", "-"),
            }
            return rsrv_dict

    @skip_exception(Exception, reraise=True)
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
                "purpose": self.tb_config.get("purpose", "-"),
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
                    "purpose": self.tb_config.get("purpose", "-"),
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
                "purpose": self.tb_config.get("purpose", "-"),
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
                "purpose": self.tb_config.get("purpose", "-"),
            }
        # analyze the last row of reservation file
        info = out.split(":::")
        # gather existing reservation message, if it exists - split apart timestamp from initial part of line
        try:
            if len(info[3].split()) > 1:
                info[3] = info[3].split()[0]
            if "+" not in info[3]:
                log.trace("Extending timestamp with +00:00 timezone information")
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
                "purpose": self.tb_config.get("purpose", "-"),
            }
        owner, mach_uuid = self.get_owner_machine_uuid()
        owner = self.tb_config.get("owner", owner)
        busy_by_me = busy and owner == info[0] and mach_uuid == info[1]
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
                "purpose": self.tb_config.get("purpose", "-"),
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
                "purpose": self.tb_config.get("purpose", "-"),
            }

    def update_old_reservation_format(self):
        """Update the file format to the latest reservation format.

        Updates separator string. Old format was using __ [double underscore] as a separator, new file format
        uses ::: [triple colon].
        """
        convert_cmd = f"flock -x {self.res_file} --command \"sudo sed -i -e 's/__/:::/g' {self.res_file}\""
        output = self._server_ssh_call(convert_cmd)
        log.info("Reservation file conversion resulted: %s", output)
        return {"name": self.tb_name, "status": True if "Error" not in output else False, "message": "-"}

    @skip_exception(Exception, reraise=True)
    def unreserve(self, by_pytest_plugin=False):
        """
        Un-reserve test bed
        """
        with lock_reserve_file(self.tb_config, self.client_lib, self.res_file):
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
            res_row = self.generate_reservation_row(
                status,
                0,
                keep_owner=True,
                by_pytest_plugin=by_pytest_plugin,
                preserve_original_reservation_message=True,
            )
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
                f'flock -x {self.res_file} --command \'sudo sed -i "$ d" {self.res_file} && '
                f'echo -e "{res_row}" | sudo tee -a {self.res_file} && sync\''
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
                f"\"echo -e '{res_row}\n$(tail -1 {self.res_file})' | sudo tee {self.res_file} && sync\""
            )
            cmd = self.ensure_res_file_cmd + file_operation_cmds

            out = self._server_ssh_call(cmd)
        else:
            out = self._server_ssh_call(f"sudo rm {self.res_file}; sync")

            file_operation_cmds = (
                f"flock -x {self.res_file} --command 'echo \"{res_row}\" | sudo tee -a {self.res_file} && sync'"
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
        log.debug("Checking for outdated reservation file started.")
        file_operation_cmds = f'flock -x {self.res_file} --command "cat {self.res_file}"'
        cmd = self.ensure_res_file_cmd + file_operation_cmds

        out = self._server_ssh_call(cmd)
        log.debug("Checking for outdated reservation file finished.")
        return "__" in out

    @skip_exception(Exception, reraise=True)
    def get_owner_machine_uuid(self, keep_owner: bool = False) -> tuple[str, str]:
        """Returns a pair: owner, machine uuid based on the current config."""
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
        return owner, mach_uuid

    @skip_exception(Exception, reraise=True)
    def generate_reservation_row(
        self,
        current_reservation: dict,
        reservation_time: int = 120,
        keep_owner: bool = False,
        by_pytest_plugin: bool = False,
        preserve_original_reservation_message: bool = False,
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
        owner, mach_uuid = self.get_owner_machine_uuid(keep_owner=keep_owner)

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
        if not preserve_original_reservation_message:
            rsrv_msg = str(self.new_reservation_msg) if self.new_reservation_msg else ""
        else:
            rsrv_msg = current_reservation["message"]
        owner = self.tb_config["owner"] if self.tb_config.get("owner") else owner
        if current_reservation["busy"]:
            is_forced = self.tb_config.get("force", current_reservation.get("is_forced", False))
        else:
            is_forced = self.tb_config.get("force", False)
        reservation_row = (
            f"{owner}:::{mach_uuid}:::{start_time}:::{end_time.isoformat()}:::{__version__}:::{is_forced}:::{rsrv_msg}"
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
                log.trace("Could not determine reservelib version")
                version = "Unknown"
            try:
                is_forced = row[5] == "True"
            except IndexError:
                log.trace("Could not determine if resrvation was forced (assuming False)")
                is_forced = False
            try:
                message = row[6]
            except IndexError:
                log.trace("Could not determine reservation message (old version of reservelib was used!)")

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
        log.debug("Obtaining latest reserve lib used, need to fetch full history to do this...")
        history = self.get_history()
        newest_ver = Version("0.0.0")
        for row in history:
            str_ver = row.get("version")
            if str_ver:
                try:
                    ver = Version(str_ver)
                    if ver.is_prerelease:
                        continue
                    if ver > newest_ver:
                        newest_ver = ver
                except ValueError:
                    pass  # happens for some pre-releases or unparseable, do nothing
        log.debug("Obtained latest stable version used: %s", newest_ver)
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
        log.trace("UTC offset: %s", offset)
        return datetime.datetime.strftime(utc_time + offset, "%Y-%m-%d %H:%M:%S")


# keeping that global, so other plugins can stop the reservation threat, e.g PyUpgradePlugin
reserve_main_q = {}
lock = threading.RLock()


class PyReservePlugin:
    def __init__(self, config_name, tb_pool_name, skip_reservation, tb_config=None):
        assert config_name, "Cannot be used without config file"
        self.config_name = config_name
        self.skip_reservation = skip_reservation
        self.reserve_t = None
        self.res = None
        self.tb_config = tb_config
        self.busy_by_me = False  # hold the information whether the testbed is busy by me

    @pytest.fixture(scope="session", autouse=True)
    def reserve_fixture(self, request):
        """Performs testbed reservation and yields testbed config (``tb_config``)"""
        self.tb_config = config.load_tb_config(self.config_name, skip_deployment=True, skip_capabilities=True)
        kwargs = {"config": self.tb_config}
        self.res = ReserveLib(**kwargs)
        self._reserve(request)
        yield
        self._unreserve(request)

    def _reserve(self, request: pytest.FixtureRequest):
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
            safe_exit_pytest(request=request, msg="Could not obtain testbed reservation")
            # this skip result will only be assigned to the currently executed test module because pytest
            # will exit/stop worker when invoking the pytest_runtest_logreport hook/tb-configurator plugin
            pytest.skip("Could not obtain testbed reservation")
            return

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

    def _unreserve(self, request: pytest.FixtureRequest):
        # the request fixture is required for consistency with reserve, so that safe_exit_pytest can be called from
        # this teardown method in case of trouble with the xdist worker.
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
                safe_exit_pytest(
                    request=item._request, msg="Testbed was force-reserved by someone else during test session."
                )
