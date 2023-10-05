"""
Logging module
"""
import allure
import json
import logging
import os
import sys
import tempfile
import time
import shutil
import threading
import inspect
import allure_commons


LOGGER_NAME = "automation"

loggers = {}


def add_stream_handler_to_logger(my_logger):
    my_logger.setLevel(logging.INFO)
    # create console handler
    stream_hdlr = logging.StreamHandler()
    stream_hdlr.setLevel(logging.DEBUG)
    # create formatter and add it to the handlers
    formatter = logging.Formatter("%(asctime)s.%(msecs)03d [%(levelname).4s] %(message)s", "%H:%M:%S")
    stream_hdlr.setFormatter(formatter)
    my_logger.addHandler(stream_hdlr)


class AllureLogger(logging.Handler):
    """Logger for capturing logs per step.

    Every log is saved to ``self.step_log_buffer``. Whenever logs need to be attached to the report
    ``get_logs_and_clear_buffer`` is called.

    Args:
        logging (_type_): _description_
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.step_log_buffer = []

    def format(self, record):
        """Override format function that assign the root logger's formatter to self."""
        if self.formatter is None:
            try:
                formatter = logging.getLogger().handlers[0].formatter
                self.setFormatter(formatter)
            except Exception as e:
                # We can't log any errors here, it could lead to infinite recursion
                pass
        return super().format(record)

    def emit(self, record):
        """``emit`` is called every time a log is emitted thus it's easy to intercept them into the buffer."""
        self.step_log_buffer.append(self.format(record))

    def get_logs_and_clear_buffer(self) -> str:
        """Returns collected logs and clears an internal buffer"""
        logs = "\n".join((self.step_log_buffer))
        self.step_log_buffer = []
        return logs


def get_logger(name):
    global loggers

    if loggers.get(name):
        return loggers.get(name)
    else:
        my_logger = logging.getLogger(LOGGER_NAME)
        if "pytest" not in sys.modules:
            add_stream_handler_to_logger(my_logger)
        if "allure" in sys.modules:
            my_logger.addHandler(AllureLogger())
        loggers[name] = my_logger
        return my_logger


def update_logger_with_stream_handler(logger):
    if not [handler for handler in logger.handlers if isinstance(handler, logging.StreamHandler)]:
        add_stream_handler_to_logger(logger)


def remove_stream_handler_from_logger(logger):
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)


logger = get_logger(LOGGER_NAME)


class MyLogger:
    """Create logger class to customize log with additional information"""

    ERROR = logging.ERROR
    WARNING = logging.WARNING
    INFO = logging.INFO
    DEBUG = logging.DEBUG

    def __init__(self):
        self.new_call = True
        self.last_attr = None
        self.new_line = True

    def __getattr__(self, attr):
        orig_attr = self.get_orig_attr(attr)
        if callable(orig_attr):

            def hooked(*args, **kwargs):
                args, kwargs = self.modify_args_kwargs(attr, *args, **kwargs)
                result = orig_attr(*args, **kwargs)
                # prevent wrapped_class from becoming unwrapped
                if result == logger:
                    return self
                return result

            return hooked
        else:
            return orig_attr

    def get_orig_attr(self, attr):
        if self.last_attr != attr:
            self.new_call = True
        else:
            self.new_call = False
        if attr == "console":
            orig_attr = self.log_console
        else:
            if self.last_attr == "console" and not self.new_line:
                # Log has changed from console to e.g. info. Start from the new line to not continue
                # in the same line as console.
                self.log_console("")
            global logger
            orig_attr = logger.__getattribute__(attr)
        self.last_attr = attr
        return orig_attr

    def get_extended_keyword(self, key, **kwargs):
        value = kwargs.get(key)
        if value != None:
            # Remove from kwargs
            kwargs.pop(key)
        else:
            value = True
        return value, kwargs

    def show_file(self, attr, **kwargs):
        value, kwargs = self.get_extended_keyword("show_file", **kwargs)
        if value and (attr != "console" or (attr == "console" and (self.new_call or self.new_line))):
            return True, kwargs
        else:
            return False, kwargs

    def check_indentation(self, **kwargs):
        value, kwargs = self.get_extended_keyword("indent", **kwargs)
        if value is not True:
            return value, kwargs
        else:
            return 0, kwargs

    def modify_args_kwargs(self, attr, *args, **kwargs):
        show_file, kwargs = self.show_file(attr, **kwargs)
        indent, kwargs = self.check_indentation(**kwargs)
        if indent:
            if isinstance(args[0], str):
                # Add whitespaces
                prefix = " " * 2 * indent
                indent_str = prefix + f"\n{prefix}".join(args[0].split("\n"))
                args = (indent_str,) + args[1:]
        if show_file:
            if args and isinstance(args[0], str):
                # Add file and line number to message
                try:
                    stack = inspect.stack()
                    file_name = os.path.basename(stack[2][1])
                    file_name = os.path.splitext(file_name)[0]
                    # Add device prefix to file_name
                    if device_name := self.capture_device_name(stack_frames=stack):
                        file_name = f"{device_name}:{file_name}"
                    if len(file_name) > 18:
                        file_name = file_name[:12] + ".." + file_name[-4:]
                    line_no = stack[2][2]
                except IndexError:
                    # In case file content has changed
                    file_name = "file has changed"
                    line_no = ""
                prefix = "[%-18s:%-4s]  " % (file_name, line_no)
                args = (prefix + args[0],) + args[1:]
        return args, kwargs

    @staticmethod
    def capture_device_name(stack_frames):
        device_name = ""
        try:
            if "lib_testbed" in stack_frames[2][1]:
                object_context = stack_frames[2].frame.f_locals.get("self", None)
                if object_context and hasattr(object_context, "name"):
                    device_name = object_context.name
        except Exception as error:
            ...
        return device_name

    def log_console(self, *args, **kwargs):
        end = kwargs.get("end")
        if end is None or end.endswith("\n"):
            self.new_line = True
        else:
            self.new_line = False
        return _log_console(*args, **kwargs)


log: logging.Logger | object = MyLogger()


def _log_console(*args, **kwargs):
    # Add delay thus print call doesn't interrupt the logging queue
    # TODO: Fix printing to stdout without EOL
    time.sleep(0.01)
    print(*args, **kwargs)
    sys.stdout.flush()
    time.sleep(0.01)


class LogCatcher:
    def __init__(self, default_name=None):
        self.loggers = []
        self.default_name = default_name
        # register each LogCatcher inside allure plugin_manager so that we can use allure_commons hooks
        allure_commons.plugin_manager.register(self)

    @allure_commons.hookimpl(tryfirst=True)
    def stop_step(self, uuid, exc_type, exc_val, exc_tb):
        """Allure hook, called on step's exit.

        The best way to implement custom step collection in LogCatcher derived class is to override ``step_collect``
        method and call ``super().step_collect(test_data)`` inside of it.
        """
        test_data = {"failed": False if exc_type is None else True}
        self.step_collect(test_data=test_data)

    def add(self, **_kwargs):
        # implement add() in a derived class
        raise NotImplementedError

    def add_screenshot(self, **_kwargs):
        # implement add_screenshot() in a derived class
        raise NotImplementedError

    def get_logger(self, name=None, source=None):
        if not name:
            name = self.default_name
        for logger in self.loggers:
            if logger.get("name") != name:
                continue
            if source and logger.get(source) != source:
                continue
            return logger
        return None

    def remove_logger(self, name=None, source=None):
        found_logger = self.get_logger(name, source)
        if found_logger:
            self.loggers.remove(found_logger)

    def get_log_buffer(self, name=None):
        logger = self.get_logger(name)
        if not logger:
            return []
        return logger["body"]

    def initial_logger(
        self, name, mime_type=allure.attachment_type.TEXT, source=None, extension=None, remove_dir=True, **kwargs
    ):
        logger = self.get_logger(name, source)
        if not logger:
            logger = {
                "name": name,
                "body": [],
                "source": source,
                "mime_type": mime_type,
                "extension": extension,
                "remove_dir": remove_dir,
            }
            self.loggers.append(logger)

        if dirs_to_remove := kwargs.pop("dirs_to_remove", None):
            logger["dirs_to_remove"] = dirs_to_remove

    def attach_file(self, file_path, name=None, mime_type=None):
        """Attach file in allure report immediately (without waiting for log collection).
        Note that file is removed after it is attached in the report,
        """
        if not mime_type:
            file_ext = os.path.splitext(file_path)[1]
            file_ext = file_ext[1:] if file_ext.startswith(".") else file_ext
            mime_type_name = file_ext.upper()
            if mime_type_name == "TXT":
                mime_type_name = "TEXT"
            try:
                mime_type = getattr(allure.attachment_type, mime_type_name)
            except AttributeError:
                raise Exception(f"Unknown mime type: {file_ext}")
        if not name:
            name = os.path.basename(file_path)
        self.initial_logger(name=name, mime_type=mime_type, source=file_path, remove_dir=False)
        self.attach_to_allure([[self.get_logger(name)]])
        self.remove_logger(name)

    def attach_as_tmp_file(self, file_path, name=None, mime_type=None):
        """Attach file in allure report immediately (without waiting for log collection).
        Note that origin file (file_path) is not removed.
        """
        prefix = os.path.basename(file_path).split(".")[0]
        suffix = os.path.splitext(file_path)[-1]
        if not name:
            name = os.path.basename(file_path)
        with tempfile.NamedTemporaryFile(prefix=prefix, suffix=suffix, delete=False) as tmp:
            shutil.copy2(file_path, tmp.name)
            self.attach_file(tmp.name, name=name, mime_type=mime_type)

    def attach_data_as_file(self, data, file_name):
        """Attach data in allure report as a file with specified file_name immediately
        (without waiting for log collection)
        """
        prefix = os.path.basename(file_name).split(".")[0]
        suffix = os.path.splitext(file_name)[-1]
        with tempfile.NamedTemporaryFile(prefix=prefix, suffix=suffix, delete=False) as tmp:
            with open(tmp.name, "w+") as fh:
                if suffix == ".json":
                    assert isinstance(data, (dict, list))
                    json.dump(data, fh, indent=2)
                elif suffix == ".txt":
                    assert isinstance(data, str)
                    fh.write(data)
                else:
                    raise Exception(f"File type: {suffix} not supported")
            self.attach_file(tmp.name, name=file_name)
        log.info(f"Data attached as {file_name}")

    def add_to_logs(self, log, name=None):
        logger = self.get_logger(name)
        if not logger:
            if not name:
                name = self.default_name
            self.initial_logger(name)
            logger = self.get_logger(name)
            assert logger
        logger["body"].append(log)

    def collect(self, test_data):
        pass

    def step_collect(self, test_data: dict):
        """Performs log collection when exitting a step.

        Args:
            test_data: contains information whether the step was successfull or not. It mimics the structure of the \
                ``test_data`` attribute of :py:meth:`LogCatcher.attach_to_allure`
        """
        self.attach_to_allure(loggers_list=[self.loggers])

    def get_all(self, test_data):
        self.collect(test_data)
        return self.loggers

    @classmethod
    def attach_logs(cls, opensync_obj, configuration_name, failed=True, has_steps=False, scope=""):
        from lib_testbed.generic.util.common import Results

        for obj in opensync_obj:
            if not hasattr(obj, "log_catcher"):
                obj.log_catcher = LogCatcher.DummyLogCatcher()
            if not hasattr(obj, "get_name"):
                obj.get_name = LogCatcher.ModuleName(obj).get_name

        jobs = []
        results_dict = {}
        objs = []
        collecting_logs = False
        test_data = {"name": configuration_name, "failed": failed, "skip_collect": False, "has_steps": has_steps}
        for _obj in opensync_obj:
            obj_list = _obj.obj_list if hasattr(_obj, "obj_list") else [_obj]
            for obj in obj_list:
                if (
                    hasattr(obj, "assoc_name")
                    and hasattr(obj.log_catcher, "cloud_base")
                    and obj.log_catcher.cloud_base
                    and id(obj) != id(obj.log_catcher.cloud_base)
                ):
                    # Don't call collect twice for userbase and custbase
                    continue
                objs.append(obj)
                new_test_data = test_data.copy()
                name = obj.get_name()
                if name.startswith("multi_") and name[len("multi_") :] in [
                    tmp_obj.get_name() for tmp_obj in opensync_obj
                ]:
                    new_test_data.update({"skip_collect": True})
                elif test_data["failed"] and not collecting_logs:
                    nickname = _obj.get_nickname() if hasattr(_obj, "get_nickname") else ""
                    if not nickname:
                        nickname = _obj.get_name() if hasattr(_obj, "get_name") else ""
                    log.info(f"[{nickname}] Collecting logs in scope {scope}...")
                    collecting_logs = True
                if not obj.log_catcher:
                    continue
                # obj.log_catcher.get_all(*args)
                thread = threading.Thread(
                    target=Results.call_method,
                    args=(
                        obj.log_catcher.get_all,
                        cls,
                        False,
                        obj,
                        results_dict,
                        new_test_data,
                    ),
                    daemon=True,
                )
                thread.start()
                jobs.append(thread)

        # device_log_catcher waits up to 180 sec for pod to be online again, so this should be more than that
        max_time = 300
        start_time = time.time()
        for job in jobs:
            exec_time = time.time() - start_time
            timeout = max_time - exec_time if exec_time < max_time else 1
            job.join(timeout=int(timeout))

        resp_loggers = Results.get_sorted_results(results_dict, objs, skip_exception=True)
        for my_loggers in resp_loggers:
            if type(my_loggers) != list:
                error = repr(my_loggers).replace("\\n", "\n")
                log.error(f"[log_catcher] error occurred:\n{error}")
        obj_loggers = [obj.log_catcher.loggers for obj in objs if obj.log_catcher]
        LogCatcher.attach_to_allure(obj_loggers)

    @staticmethod
    def attach_to_allure(loggers_list):
        attachments = []
        dir_paths = []
        for my_loggers in loggers_list:
            for my_logger in my_loggers:
                if not my_logger:
                    continue
                if my_logger.get("attached"):
                    continue
                if my_logger["name"] in attachments:  # and logger['name'].startswith('log_pull'):
                    continue
                if my_logger.get("body"):
                    allure.attach(
                        "\n".join(my_logger["body"]), name=my_logger["name"], attachment_type=my_logger["mime_type"]
                    )
                    # clean the body, so in case of next log attach, only new logs will be included
                    my_logger["body"] = []
                elif my_logger.get("source"):
                    src_file = my_logger["source"]
                    if not os.path.exists(src_file):
                        log.error(f"File {src_file} not found")
                        continue
                    allure.attach.file(
                        source=src_file,
                        name=my_logger["name"],
                        attachment_type=my_logger["mime_type"],
                        extension=my_logger["extension"],
                    )
                    os.remove(src_file)
                    # do not attach the same file again
                    my_logger["attached"] = True
                    if my_logger.get("remove_dir"):
                        dir_paths.append(os.path.dirname(src_file))
                    if dirs_to_remove := my_logger.get("dirs_to_remove"):
                        dir_paths.extend(dirs_to_remove)
                else:
                    continue
                attachments.append(my_logger["name"])
        for dir_path in set(dir_paths):
            # log.info(f"Removing {dir_path}")
            shutil.rmtree(dir_path, ignore_errors=True)

    class DummyLogCatcher:
        loggers = []

        def get_all(*_args, **_kwargs):
            return []

    class ModuleName:
        def __init__(self, self_obj):
            self.obj = self_obj

        def get_name(self):
            my_name = self.obj.__class__.__name__
            if my_name == "module":
                my_name = self.obj.__name__.split(".")[-1]
            # log.info(f"[Log catcher] Consider to implement get_name() in: {my_name}")
            return my_name


class XdistStreamHandler(logging.StreamHandler):
    """Helper to split record containing new lines to records - one per line."""

    def __init__(self):
        super(XdistStreamHandler, self).__init__()

    def emit(self, record):
        try:
            messages = str(record.msg).split("\n")
        except Exception as e:
            log.exception(f"[XdistStreamHandler] Failed to convert into string: {record.msg}")
            messages = [record.msg]
        for message in messages:
            record.msg = message
            super(XdistStreamHandler, self).emit(record)


def setup_xdist_logger(config):
    from lib_testbed.generic.util.pytest_config_utils import get_option_config_name, get_option_config_names

    # Add worker prefix only in case xdist is used
    if hasattr(config, "workerinput") and not config.option.disable_xdist_live_logging:
        worker_id = config.workerinput["workerid"]
        config_name = full_config_name = get_option_config_name(config)
        offset = 1
        if config_name:
            names = get_option_config_names(config)
            max_name_length = max([len(name) for name in names])
            offset = offset + max_name_length - len(full_config_name)
            if full_config_name.endswith("-web"):
                config_name = config_name[:-4]
        worker_name = config_name if config_name else worker_id
        full_message = f"<{worker_name}>{offset * ' '}{{message}}"

        console_handler = XdistStreamHandler()

        if not config.option.enable_colored_xdist:
            fmt = full_message
        else:
            red = 31
            green = 32
            yellow = 33
            blue = 34
            pink = 35
            cyan = 36
            grey = 38

            reset = "\x1b[0m"

            colors = [red, green, yellow, blue, pink, cyan, grey]
            color = colors[int(worker_id[2:]) % len(colors)]
            color = f"\x1b[{color};20m"
            fmt = color + full_message + reset

        console_handler.setFormatter(
            logging.Formatter(
                # Include worker id in log messages
                fmt=fmt,
                style="{",
            )
        )
        # Configure logging
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)

        if config_name:
            log.info(f"Worker: `{worker_id}` is assigned to config: `{full_config_name}`")
