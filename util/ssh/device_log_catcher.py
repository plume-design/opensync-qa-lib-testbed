import datetime
import gzip
import os
import re
import shutil
import time
import zlib
import subprocess
from multiprocessing import Lock
from lib_testbed.generic.util.logger import log, LogCatcher

DEBUG = False

lock = Lock()


class DeviceLogCatcher(LogCatcher):
    def __init__(self, obj, **kwargs):
        super().__init__(**kwargs)
        self.obj = obj

    def get_name(self):
        return self.obj.get_name()

    def add(self, command, new_commands, result, device, start_time):
        start = datetime.datetime.now() - datetime.timedelta(seconds=int(time.time() - start_time))
        start = f"{start.hour:02d}:{start.minute:02d}:{start.second:02d}"
        name = device.name
        self.add_to_logs(f'{start} [{name}] --> {command} [duration: {time.time() - start_time:.2f}s]\n')
        if DEBUG:
            self.add_to_logs(f"Remote command: {new_commands[name]}")
            log.info(f'Response for cmd: {command}\n{result[name][1]}')
        if not result[name][0]:
            info = result[name][1]
            error = ''
        else:
            info = result[name][2]
            error = f'[ERROR] ret:{result[name][0]}, stderr: '
            if DEBUG:
                log.error(error)
        # assert info is not None
        if isinstance(info, bytes):
            info = str(info)
        if self.obj.config.get('log_to_console'):
            log_entry = f"[SSH] {name}: {command}"
            # Add SSH response in case full log flag
            if self.obj.config['log_to_console'] == 'full':
                log_entry += f"\n{result[name]}"
            log.info(log_entry, show_file=False)
        self.add_to_logs(f"{error}{info}")

    def add_mock(self, command, result, dev_name):
        def get_variable_name(cmd, suffix):
            # Remove all non-word characters (everything except numbers and letters)
            name = re.sub(r"[^\w\s]", '_', cmd)
            # Replace multiple '_' by single '_'
            pattern = '_' + '{1,}'
            name = re.sub(pattern, '_', name)

            # Replace multiple occurrences of a character by a single character
            name = re.sub(r"\s+", '_', name)
            name = name.lower()
            name = name.lstrip('_')
            name = name.rstrip('_')
            short_name = ''
            for word in reversed(name.split('_')):
                if not word or word.isdigit():
                    continue
                if short_name:
                    short_name = '_' + short_name
                short_name = (word if len(word) < 10 else word[:10]) + short_name
                if 'end_sign' in short_name:
                    short_name = ''
                if len(short_name) > 10:
                    break
            short_name = short_name.rstrip('_')
            short_name = short_name.lstrip('_')
            return f'{short_name}_{suffix}'

        mock_logger_name = f"mock_{self.obj.device_type.lower()}_{self.obj.get_name()}"
        buffer = self.get_log_buffer(name=mock_logger_name)
        init_resp = ', init=False' if buffer else ', init=True'
        names_resp = ', self.names' if self.obj.multi_devices else ''
        ret_value = result[dev_name][0]
        stdout = result[dev_name][1]
        stderr = result[dev_name][2]
        if isinstance(stdout, bytes):
            stdout = str(stdout)
        if isinstance(stderr, bytes):
            stderr = str(stderr)
        stdout = stdout.replace('\"', '\\"').replace('\'', '\\').replace('\n', '\\n')
        stderr = stderr.replace('\"', '\\"').replace('\'', '\\').replace('\n', '\\n')
        variable_stdout = 'resp_stdout'
        set_variable_stdout = f"{variable_stdout} = '{stdout}'"
        if len(set_variable_stdout) > 120 - 8:
            set_variable_stdout += '  # noqa E501'
        if stderr:
            variable_stderr = 'resp_stderr'
            set_variable_stderr = f"{variable_stderr} = '{stderr}'"
            if len(set_variable_stderr) > 120 - 8:
                set_variable_stderr += '  # noqa E501'
            set_variable_stderr += '\n'
        else:
            set_variable_stderr = ''
            variable_stderr = "''"
        cmd_str = command.replace("\r", "\\r").replace("\n", "\\n")
        variable_cmd = 'cmd'
        set_variable_cmd = f'{variable_cmd} = \'{cmd_str}\''
        if len(set_variable_cmd) > 120 - 8:
            set_variable_cmd += '  # noqa E501'
        set_response = f'self.mock_ssh_resp.set_response({ret_value}, {variable_stdout}, {variable_stderr}' \
                       f'{names_resp}{init_resp}, {variable_cmd}={variable_cmd})'
        if len(set_response) > 120 - 8:
            set_response += '  # noqa E501'
        mock_resp = f'\n\n{set_variable_cmd}\n' \
                    f'{set_variable_stdout}\n' \
                    f'{set_variable_stderr}' \
                    f'{set_response}\n\n'
        if DEBUG:
            log.debug(mock_resp)
        self.add_to_logs(mock_resp, name=mock_logger_name)

    def collect(self, test_data):  # noqa: C901
        if not test_data.get('failed') or test_data.get('skip_collect'):
            return
        # collect logs for main device objects only
        # in case of optional mgmt access device is None, so we are not able to get anything
        if self.obj.device is None or not self.obj.main_object:
            return
        dev_name = self.obj.get_name()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        # make sure dirs are unique per device, so we can remove it completely after allure attach
        log_pull_dir = f'/tmp/automation/log_pull/{test_data["name"]}_{dev_name}_{timestamp}'
        with lock:
            try:
                os.makedirs(log_pull_dir)
            except FileExistsError:
                return
        # store jenkins info for debugging purposes
        system_info = f"BUILD_URL: {os.getenv('BUILD_URL', 'none')}\n"
        system_info += f"Date: {subprocess.run(['date'], stdout=subprocess.PIPE).stdout.decode()}\n"
        system_info += f"Device_log_catcher: 2.0.7\n"
        with open(os.path.join(log_pull_dir, 'system_info.txt'), "w+") as f:
            f.write(system_info)

        log.debug(f'Initiate log_pull: {log_pull_dir}')
        device_type = 'client' if self.obj.device_type == 'Clients' else 'pod'
        if device_type == 'pod':
            # sometimes error occurs while pod is rebooting, so wait till device is available
            self.obj.wait_available(180, skip_exception=True)
            pod_date_time = self.obj.get_datetime(skip_exception=True)
            if pod_date_time and pod_date_time.year < 1980:
                log.warning(f"Pod {dev_name} date: {pod_date_time}, zip cannot work on dates < 1980, trying to fix")
                self.obj.set_datetime(datetime.datetime.now(), skip_exception=True)
                time.sleep(1)
                log.info(f'Pod {dev_name} time now: {self.obj.get_datetime(skip_exception=True)}')
            log_pull_gzip = self.obj.get_stdout(self.obj.get_logs(log_pull_dir, timeout=120, skip_logging=True),
                                                skip_exception=True)
            if not log_pull_gzip:
                log.error(f"[{dev_name}] Failed to collect Pod log-pull, removing {log_pull_dir}")
                shutil.rmtree(log_pull_dir, ignore_errors=True)
                return
            # Re-compress archive to zip as allure currently doesn't support gzip
            log_pull_file_name = os.path.basename(log_pull_gzip).split(".")[0]
            extract_dir = os.path.join(os.path.dirname(log_pull_gzip), log_pull_file_name)
            with lock:
                # Method unpack_archive() uses unsafe os.chdir()
                # If a thread attempts to hold a lock that’s already held by some other thread,
                # execution of this thread is halted until the lock is released.
                cwd_path = os.getcwd()
                try:
                    shutil.unpack_archive(log_pull_gzip, extract_dir=extract_dir)
                except (shutil.ReadError, zlib.error, gzip.BadGzipFile) as e:
                    log.error(f"[{dev_name}] Cannot unpack logs, removing {log_pull_dir}:\n{e}")
                    shutil.rmtree(log_pull_dir, ignore_errors=True)
                    return
                finally:
                    try:
                        tmp_cwd_path = os.getcwd()
                    except FileNotFoundError:
                        tmp_cwd_path = ""
                    if tmp_cwd_path != cwd_path:
                        # unpack_archive might change directory
                        log.error("Root directory has changed, restore it.")
                        os.chdir(cwd_path)
            root_dir = extract_dir
            os.remove(log_pull_gzip)
        else:  # client
            root_dir = os.path.join(log_pull_dir, 'tmp')
            try:
                os.makedirs(root_dir)
            except FileExistsError:
                pass
            dmesg = self.obj.get_stdout(self.obj.run_command('dmesg -T', skip_logging=True, timeout=60),
                                        skip_exception=True), 'dmesg'
            iwconfig = self.obj.get_stdout(self.obj.run_command('iwconfig', skip_logging=True),
                                           skip_exception=True), 'iwconfig'
            ip_a = self.obj.get_stdout(self.obj.run_command('ip a', skip_logging=True), skip_exception=True), 'ip_a'
            uptime = self.obj.get_stdout(self.obj.run_command('uptime', skip_logging=True),
                                         skip_exception=True), 'uptime'
            wpa_supplicant_log = self.obj.get_wpa_supplicant_file(lines=10000, extension='log',
                                                                  timeout=60, skip_logging=True), 'wpa_supplicant_log'
            wpa_supplicant_conf = self.obj.get_wpa_supplicant_file(lines=10000, extension='conf',
                                                                   timeout=60, skip_logging=True), 'wpa_supplicant_conf'
            for command_dump in [dmesg, iwconfig, ip_a, uptime, wpa_supplicant_log, wpa_supplicant_conf]:
                if not command_dump[0]:
                    continue
                with open(os.path.join(root_dir, command_dump[1]), "w+") as f:
                    f.write(command_dump[0])

        log_pull_zip = os.path.join(log_pull_dir, 'log-pull')

        try:
            if not any(os.scandir(root_dir)):
                log.error(f"Getting logs from {dev_name} failed, nothing to pack. Removing storing dir: {log_pull_dir}")
                shutil.rmtree(log_pull_dir, ignore_errors=True)
                return
        except FileNotFoundError:
            pass

        with lock:
            # Method make_archive() uses unsafe os.chdir()
            # If a thread attempts to hold a lock that’s already held by some other thread,
            # execution of this thread is halted until the lock is released.
            cwd_path = os.getcwd()
            try:
                # Duplicating/Over-riding shutil.make_archive and shutil.make_zipfile.
                # This is required to create ZIP file with content that is older than 1980.
                # log_pull_zip = shutil.make_archive(log_pull_zip, 'zip', root_dir)
                log_pull_zip = self.make_archive(log_pull_zip, 'zip', root_dir)
            except (ValueError, FileNotFoundError) as e:
                log.error(f'Cannot create zip: {e}')
                log.error(f"Creating zip for {dev_name} failed, nothing to pack. Removing storing dir: {log_pull_dir}")
                shutil.rmtree(log_pull_dir, ignore_errors=True)
            finally:
                try:
                    tmp_cwd_path = os.getcwd()
                except FileNotFoundError:
                    tmp_cwd_path = ""
                if tmp_cwd_path != cwd_path:
                    log.error("Root directory has changed, restore it.")
                    os.chdir(cwd_path)
        shutil.rmtree(root_dir)
        self.initial_logger(name=f'log_pull_{device_type}_{dev_name}',
                            mime_type="application/gzip", source=log_pull_zip, dirs_to_remove=(log_pull_dir,))

    #
    # Duplicating/Over-riding shutil.make_archive and shutil.make_zipfile:
    #   shutil.make_archive calls shutil.make_zipfile but does not provide a way
    #   to pass parameter 'strict_timestamps' to shutil.make_zipfile.
    #   The 'strict_timestamps' param is need to zip files older than 1980.
    #
    def make_archive(self, base_name, format, root_dir=None, base_dir=None, verbose=0,
                     dry_run=0, owner=None, group=None, logger=None):
        save_cwd = os.getcwd()
        if root_dir is not None:
            if logger is not None:
                logger.debug("changing into '%s'", root_dir)
            base_name = os.path.abspath(base_name)
            if not dry_run:
                os.chdir(root_dir)

        if base_dir is None:
            base_dir = os.curdir

        kwargs = {'dry_run': dry_run, 'logger': logger}

        try:
            filename = self.make_zipfile(base_name, base_dir, **kwargs)
        finally:
            if root_dir is not None:
                if logger is not None:
                    logger.debug("changing back to '%s'", save_cwd)
                os.chdir(save_cwd)

        return filename

    def make_zipfile(self, base_name, base_dir, verbose=0, dry_run=0, logger=None):
        """Create a zip file from all the files under 'base_dir'.

        The output zip file will be named 'base_name' + ".zip".  Returns the
        name of the output zip file.
        """
        import zipfile  # late import for breaking circular dependency

        zip_filename = base_name + ".zip"
        archive_dir = os.path.dirname(base_name)

        if archive_dir and not os.path.exists(archive_dir):
            if logger is not None:
                logger.info("creating %s", archive_dir)
            if not dry_run:
                os.makedirs(archive_dir)

        if logger is not None:
            logger.info("creating '%s' and adding '%s' to it",
                        zip_filename, base_dir)

        if not dry_run:
            with zipfile.ZipFile(zip_filename, "w",
                                 compression=zipfile.ZIP_DEFLATED, strict_timestamps=False) as zf:
                path = os.path.normpath(base_dir)
                if path != os.curdir:
                    zf.write(path, path)
                    if logger is not None:
                        logger.info("adding '%s'", path)
                for dirpath, dirnames, filenames in os.walk(base_dir):
                    for name in sorted(dirnames):
                        path = os.path.normpath(os.path.join(dirpath, name))
                        zf.write(path, path)
                        if logger is not None:
                            logger.info("adding '%s'", path)
                    for name in filenames:
                        path = os.path.normpath(os.path.join(dirpath, name))
                        if os.path.isfile(path):
                            zf.write(path, path)
                            if logger is not None:
                                logger.info("adding '%s'", path)

        return zip_filename
