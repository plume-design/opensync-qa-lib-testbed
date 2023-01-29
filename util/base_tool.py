import os
import sys
import inspect
import traceback
import logging
import argparse
import json
import operator
import collections
from typing import Any, Callable, Dict
import terminaltables
from textwrap import wrap
from lib_testbed.generic.util import config
from lib_testbed.generic.util.ssh.parallelssh import get_success_names
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.logger import LOGGER_NAME


HELP_DOC_OFFSET = 60
BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", '..', '..'))
if os.path.exists(os.path.join(BASE_DIR, 'lib_testbed/generic/tools/')):
    TOOLS_DIR = os.path.join(BASE_DIR, 'lib_testbed/generic/tools/')
else:
    raise FileNotFoundError(f'Missing tools/ folder in {BASE_DIR}/lib_testbed/generic/')


class BaseTool:
    def __init__(self, args, tb_config=None):
        """Base class for a command-line tool/script. It defines the methods
        that need to be implemented by the actual tools, as well as common
        functionality.
        Arguments:
            args - list of command-line flags
        """
        assert args
        self.args = args[:]
        self.parser_help = ''
        self.tb_config = tb_config
        self.tool_name = args[0].split("/")[-1]
        self.parsed_args = self.arg_parser(self.args)
        self.debug = self.parsed_args.debug
        self.json_output = self.parsed_args.json
        self.timeout = getattr(self.parsed_args, 'timeout', None)
        self.set_log_level(self.debug)
        self.commands, self.base_obj = self.get_command_list(self.parsed_args)

    @staticmethod
    def set_log_level(debug: bool):
        """Sets log level to warning or debug depending on the bool argument debug"""
        # Set logging level
        logger = logging.getLogger(LOGGER_NAME)
        if not debug:
            logger.setLevel(logging.WARNING)
        else:
            logger.setLevel(logging.DEBUG)

    @staticmethod
    def get_command_list(parsed_args: argparse.Namespace, **kwargs):
        """Returns a tuple with 2 elements. The first element is a list of commands (string),
        the second element is a reference to the instance of the tool being implemented."""
        raise NotImplementedError

    def arg_parser(self, args):
        """The implementation of this method is supposed to define common arguments,
        and then parse them using argparse."""
        raise NotImplementedError

    @staticmethod
    def add_cmd_arguments(parser: argparse.ArgumentParser):
        """Add cmd arg to existing parser"""
        parser.add_argument('cmd', help="Command to be executed")
        parser.add_argument('cmd_args', nargs=argparse.REMAINDER)

    @staticmethod
    def add_name_cmd_arguments(parser: argparse.ArgumentParser):
        """Add cmd and name args to existing parser"""
        parser.add_argument('name', help="Name of device/testbed/client/pod")
        parser.add_argument('cmd', help="Command to be executed")
        parser.add_argument('cmd_args',
                            nargs=argparse.REMAINDER,
                            help="Additional optional arguments for the command")

    @staticmethod
    def format_output(cmd, response, base_obj, json_output):
        raise NotImplementedError

    @staticmethod
    def modify_initial_args(args):
        if len(args) == 1:
            args.append('help')
            return
        for i, arg in enumerate(args):
            if i == 0:
                continue
            if arg in ['-h', '--help'] and (i == 1 or args[i - 1].startswith("-")):
                args[i] = 'help'
                break

    @staticmethod
    def inspect_function(func: Callable) -> collections.namedtuple:
        """Returns a namedtuple with function/method signature"""
        return inspect.getfullargspec(func)

    def execute(self):  # noqa: C901
        """Triggers command execution. If help is requested, then it prints out the help.
        Otherwise a command is executed for the tool that the child class implements."""
        self.check_if_correct_command_called()
        func = self.commands[self.parsed_args.cmd]
        default_func_args = self.get_function_args_with_default_values(func)
        if self.is_help_on_method_called():
            output = self.get_command_help_str()
            print(output)
        else:
            args, kwargs = self.parse_cmd_arguments_to_args_and_kwargs(default_func_args)
            output = self.call_method(func, *args, **kwargs)

        return output

    def get_tool_help(self, cmd: str, verbose: bool = True, prefix: str = None, not_callable: bool = True):
        """
        Prepare helper print for all commands
        Args:
            cmd: (str) command name
            verbose: (bool) include verbose info
            prefix: (str) tool prefix, eg "{0} {{<{0}_name>[,...] | all}} {1}", where 0 is tool_name, 1 is command
            not_callable: (bool)

        Returns: (str) help message for command

        """
        tool_name = self.tool_name
        if prefix:
            result = prefix.format(tool_name, cmd)
        else:
            result = f"{tool_name} {{<{tool_name}_name>[,...] | all}} {cmd}"
        if cmd == 'help':
            return result
        if not_callable:
            fcn = self.commands[cmd](not_callable=True)[0]
        else:
            fcn = self.commands[cmd]
        arg_spec = inspect.getfullargspec(fcn)
        # args, varargs, keywords, defaults = inspect.getargspec(fcn)
        args = arg_spec.args
        if "self" in args:
            args.remove("self")
        if arg_spec.defaults:
            default_arg = dict(list(zip(arg_spec.args[-len(arg_spec.defaults):], arg_spec.defaults)))
        else:
            default_arg = {}

        for a in args:
            if a in default_arg:
                value = default_arg[a]
                if isinstance(value, str):
                    value = f"'{value}'"
                result += f" <{a}={value}>"
            else:
                result += f" <{a}>"
        if inspect.getdoc(fcn) is not None and verbose:
            if inspect.getdoc(fcn) is not None and verbose:
                desc_offset = " " * (HELP_DOC_OFFSET - len(result)) + " \t"
                new_line_offset = "\n" + " " * len(result) + desc_offset
                result += desc_offset + new_line_offset.join(inspect.getdoc(fcn).split("\n\n")[0].splitlines())
        return result

    def get_command_help_str(self) -> str:
        """Returns docstrings for a tool based on the obj_list attribute."""
        if hasattr(self.tool, "obj_list"):
            attr = self.tool.obj_list[0].__getattribute__(self.map_commands_to_method_names[self.parsed_args.cmd])
            return inspect.getdoc(attr)
        else:
            return inspect.getdoc(self.tool.__getattribute__(self.map_commands_to_method_names[self.parsed_args.cmd]))

    def get_tool_help_str(self, **kwargs) -> str:
        """Returns a string with help output extended with a
        list of available commands."""
        help_cmds = []
        for cmd in list(self.commands.keys()):
            help_cmds.append(self.get_tool_help(cmd))
        return self.parser_help + '\n'.join(help_cmds)

    def check_if_correct_command_called(self):
        """Method verifies if called method is included in self.commands """
        if self.parsed_args.cmd not in self.commands:
            log.error("Unexpected '{}' method: {}".format(
                      self.base_obj.__class__.__name__ if self.base_obj
                          else self.__class__.__name__,
                      self.parsed_args.cmd))
            exit(1)

    def get_function_args_with_default_values(self, func: Callable) -> Dict[str, Any]:
        """Returns a dict mapping method arguments to its defaults. Returns
        an empty dict if the method doesn't have arguments with defaults."""
        arg_spec = self.inspect_function(func)
        if arg_spec.defaults:
            default_arg = dict(list(zip(arg_spec.args[-len(arg_spec.defaults):], arg_spec.defaults)))
        else:
            default_arg = {}

        return default_arg

    def check_if_correct_number_of_parameters_are_passed(self, default_func_args: Dict[str, Any], func):

        default_len = len(default_func_args)
        fixed_params_length = len(self.parsed_args.cmd_args)
        if len(self.parsed_args.cmd_args) < fixed_params_length - default_len:  # TODO: fix
            # self.check_if_help_on_method_is_called(func)
            raise Exception(f"Not enough parameters\n"
                            f"Usage: {self.get_tool_help(self.parsed_args.cmd, verbose=False)}")

    def parse_cmd_arguments_to_args_and_kwargs(self, default_func_args):
        args = []
        kwargs = {}
        for param in self.parsed_args.cmd_args:
            key = None
            if self.parsed_args.cmd != 'run' and "=" in param:
                kwarg_list = param.split('=')
                arg = kwarg_list[1]
                key = kwarg_list[0]
            else:
                arg = param
            # Console arguments are always string type. If the argument is included in default_arg,
            # we can assume the expected type of the argument and cast input argument if needed.
            if key:
                if isinstance(arg, str) and key in default_func_args and isinstance(default_func_args[key], bool):
                    if arg.lower() in {"1", "yes", "true", "on"}:
                        arg = True
                    elif arg.lower() in {"", "0", "no", "false", "off"}:
                        arg = False
                    else:
                        exit(f"Invalid value: {arg} for argument: {key}. Expecting bool value")
                elif isinstance(arg, str) and key in default_func_args and isinstance(default_func_args[key], int):
                    try:
                        arg = int(arg)
                    except ValueError:
                        exit(f"Invalid value: {arg} for argument: {key}. Expecting integer value")
                kwargs[key] = arg
            else:
                args.append(arg)

        self.update_timeout_arg_if_needed(kwargs)
        return args, kwargs

    def update_timeout_arg_if_needed(self, kwargs):
        if self.timeout:
            kwargs.update({'timeout': self.timeout})

    def call_method(self, method: Callable, *args, **kwargs):
        """Calls given method with given positional arguments (args) and
        keyword arguments (kwargs). In case of an error, the method
        prints out part of a traceback if debug is enabled,
        and then it prints out help usage."""
        try:
            response = method(*args, **kwargs)
        except Exception:
            if self.debug:
                traceback.print_exc(limit=2, file=sys.stdout)
            else:
                log.warning("Add -D to enable debug logs.")
            log.error(f"Failed to execute {self.base_obj.__class__.__name__ if self.base_obj else None}"
                      f" command: {self.parsed_args.cmd} {' '.join(self.parsed_args.cmd_args)}")
            print(f"Usage: {self.get_tool_help(self.parsed_args.cmd, verbose=False)}")
            raise

        return self.format_output(self.parsed_args.cmd, response, self.base_obj, self.json_output)

    def is_help_on_method_called(self) -> bool:
        """Returns True if the command the flags -h, --help, or just
        plain help is given by the user"""
        is_called = self.parsed_args.cmd != 'help' and any(
            help_arg in self.parsed_args.cmd_args for help_arg in ['help', '--help', '-h'])
        return is_called

    def get_latest_index_of_optional_parameter(self, args):
        for index, arg in enumerate(args):
            if arg in self.map_commands_to_method_names:
                break
            elif '-' in arg[0] and (index + 1) == len(args):
                return index
            elif '-' in arg[0] and '-' not in args[index + 1][0]:
                return index
        return 0

    def map_commands_to_objects(self, tool) -> Dict:

        mapped_commands = {}
        for command, method_name in self.map_commands_to_method_names.items():

            if "help" in command:
                mapped_commands[command] = getattr(self, method_name)
            else:
                mapped_commands[command] = getattr(tool, method_name)

        return mapped_commands


class ClientPodTool(BaseTool):
    def modify_initial_args(self, args):
        super().modify_initial_args(args)
        last_opt_param = self.get_latest_index_of_optional_parameter(args)
        if (last_opt_param + 1) == len(args) or not any(
           client in args[last_opt_param + 1] for client in self.client_list + self.node_list + ['host', 'all']):
            args.insert(1, "all")

    def arg_parser(self, args):
        self.modify_initial_args(args)
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-D', '--debug', action="store_true", help="Enable debug logs")
        parser.add_argument('-j', '--json', action="store_true", help="Set output type: json")
        parser.add_argument('-t', '--timeout', type=int, action=None, help="Set timeout for ssh request")
        self.add_name_cmd_arguments(parser)
        self.parser_help = f"{parser.format_help()}\n\nAvailable methods:\n"
        parsed_args = parser.parse_args(args[1:])

        if parsed_args.debug:
            args.remove('-D')

        return parsed_args

    def get_nicknames(self, parsed_args):
        names = parsed_args.name.split(",")
        if names == ['all']:
            names = []
        return names

    def get_config(self):
        if not self.tb_config:
            self.tb_config = config.load_tb_config(skip_deployment=True)
        return self.tb_config

    @staticmethod
    def format_output(cmd, response, obj, json_output):
        if cmd == 'help':
            response = [0, response, '']
            if obj.multi_devices:
                response = [response] * len(obj.device)
        assert isinstance(response, list)
        if json_output:
            out = {}
            for i, resp in enumerate(response):
                if not isinstance(resp, list):
                    if isinstance(resp, BaseException) or \
                            isinstance(resp, str) and resp.startswith('Traceback (most recent call last):'):
                        raise Exception(resp)
                    raise Exception(f"Response is not a list\n{resp}")
                assert len(resp) == 3
                json_out = {obj.get_nickname()[i]: {"ret_value": resp[0], "stdout": resp[1], "stderr": resp[2]}}
                print(json.dumps(json_out))
                out.update(json_out)
            return out
        else:
            table = []
            if cmd in ['help']:
                out = response[0][1]
                print(out)
                return response
            elif cmd in ['list']:
                names = []
                for resp in response:
                    names.append(resp[1])
                print("\n".join(names))
                return response
            for i, name in enumerate(obj.get_nicknames()):
                out = response[i]
                if not isinstance(out, list):
                    if isinstance(response[i], Exception):
                        out = [1, '', repr(out).replace('\\n', '\n')]
                        response[i] = out
                    else:
                        raise Exception(f"Unexpected response type: {type(response[i])}, expecting list. "
                                        f"Response: \n{response[i]}")
                ret_value = out[0]
                # terminaltables incorrectly counts number of lines when they use any other line separator
                # than \n, and then cuts off all lines that go over its (incorrectly) calculated limit.
                # for get-ips, the out[1] is a dict, converting to str
                if isinstance(out[1], dict):
                    out[1] = str(out[1])
                stdout = "\n".join(out[1].splitlines())
                stderr = "\n".join(out[2].splitlines())
                table.append([name, ret_value, stdout, stderr])
            table = sorted(table, key=operator.itemgetter(0))
            table.insert(0, ['NAME', '$?', 'STDOUT', 'STDERR'])
            print(terminaltables.DoubleTable(table).table)
            successful_clients = get_success_names(response, obj.get_nicknames())
            if len(successful_clients) == len(obj.name):
                return response
            elif len(successful_clients) == 0:
                exit(1)
            else:
                exit(2)

    def inspect_function(self, func):
        # Need to be overwritten due to wrapped function by hooked()
        closure_vars = inspect.getclosurevars(func).nonlocals
        func_objects = closure_vars['self_obj'].obj_list if closure_vars.get('self_obj') else []
        default_function = None
        for func_obj in func_objects:
            default_function = getattr(func_obj, closure_vars['attr_name'], None)
            if default_function:
                break
        function_to_inspect = default_function if default_function else func
        return inspect.getfullargspec(function_to_inspect)

    def method_index_in_args(self, args):
        commands = self.map_commands_to_method_names
        for arg in args:
            if arg in commands:
                return args.index(arg)

    @property
    def client_list(self):
        config = self.get_config()
        return [client['name'] for client in config['Clients']]

    @property
    def node_list(self):
        config = self.get_config()
        return [node['name'] for node in config['Nodes']]


class ServerToolBase(ClientPodTool):
    def get_nicknames(self, parsed_args):
        return ['host']

    def modify_initial_args(self, args):
        if len(args) == 1:
            args.append('help')
            return
        for i, arg in enumerate(args):
            if i == 0:
                continue
            if arg in ['-h', '--help'] and (i == 1 or args[i - 1].startswith("-")):
                args[i] = 'help'
                break

    def arg_parser(self, args):
        self.modify_initial_args(args)
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-D', '--debug', action="store_true", help="Enable debug logs")
        parser.add_argument('-j', '--json', action="store_true", help="Set output type: json")
        parser.add_argument('-t', '--timeout', type=int, help="Set timeout for ssh request")
        self.add_cmd_arguments(parser)
        self.parser_help = f"{parser.format_help()}\n\nAvailable methods:\n"
        parsed_args = parser.parse_args(args[1:])
        if parsed_args.debug:
            args.remove('-D')
        return parsed_args

    def get_tool_help(self, cmd, verbose=True, prefix=None, not_callable=True):
        """
        Prepare helper print for all commands
        Args:
            cmd: (str) command name
            verbose: (bool) include verbose info
            prefix: (str) tool prefix, eg "{0} {1}", where 0 is tool_name, 1 is command
            not_callable: (bool)

        Returns: (str) help message for command

        """
        tool_name = self.tool_name
        if prefix:
            result = prefix.format(tool_name, cmd)
        else:
            result = f"{tool_name} {cmd}"
        if cmd == 'help':
            return result
        if not_callable:
            fcn = self.commands[cmd](not_callable=True)[0]
        else:
            fcn = self.commands[cmd]
        arg_spec = inspect.getfullargspec(fcn)
        # args, varargs, keywords, defaults = inspect.getargspec(fcn)
        args = arg_spec.args
        if "self" in args:
            args.remove("self")
        if arg_spec.defaults:
            default_arg = dict(list(zip(arg_spec.args[-len(arg_spec.defaults):], arg_spec.defaults)))
        else:
            default_arg = {}

        for a in args:
            if a in default_arg:
                value = default_arg[a]
                if isinstance(value, str):
                    value = f"'{value}'"
                result += f" <{a}={value}>"
            else:
                result += f" <{a}>"
        if inspect.getdoc(fcn) is not None and verbose:
            if inspect.getdoc(fcn) is not None and verbose:
                desc_offset = " " * (HELP_DOC_OFFSET - len(result)) + " \t"
                new_line_offset = "\n" + " " * len(result) + desc_offset
                result += desc_offset + new_line_offset.join(inspect.getdoc(fcn).split("\n\n")[0].splitlines())
        return result

    @staticmethod
    def format_output(cmd, response, obj, json_output):
        if cmd == 'help':
            response = [0, response, '']
            if obj.multi_devices:
                response = [response] * len(obj.device)
        assert isinstance(response, list)
        if json_output:
            out = {}
            for i, resp in enumerate(response):
                if not isinstance(resp, list):
                    if isinstance(resp, BaseException) or \
                            isinstance(resp, str) and resp.startswith('Traceback (most recent call last):'):
                        raise Exception(resp)
                    raise Exception(f"Response is not a list\n{resp}")
                assert len(resp) == 3
                json_out = {obj.get_nickname()[i]: {"ret_value": resp[0], "stdout": resp[1], "stderr": resp[2]}}
                print(json.dumps(json_out))
                out.update(json_out)
            return out
        else:
            table = []
            if cmd in ['help']:
                out = response[0][1]
                print(out)
                return response
            elif cmd in ['list']:
                names = []
                for resp in response:
                    names.append(resp[1])
                print("\n".join(names))
                return response
            for i, name in enumerate(obj.get_nicknames()):
                out = response[i]
                if not isinstance(out, list):
                    if isinstance(response[i], Exception):
                        out = [1, '', repr(out).replace('\\n', '\n')]
                        response[i] = out
                    else:
                        raise Exception(f"Unexpected response type: {type(response[i])}, expecting list. "
                                        f"Response: \n{response[i]}")
                ret_value = out[0]
                # terminaltables incorrectly counts number of lines when they use any other line separator
                # than \n, and then cuts off all lines that go over its (incorrectly) calculated limit.
                stdout = "\n".join(out[1].splitlines())
                stderr = "\n".join(out[2].splitlines())
                table.append([ret_value, stdout, stderr])
            table = sorted(table, key=operator.itemgetter(0))
            table.insert(0, ['$?', 'STDOUT', 'STDERR'])
            print(terminaltables.DoubleTable(table).table)
            successful_clients = get_success_names(response, obj.get_nicknames())
            if len(successful_clients) == len(obj.name):
                return response
            elif len(successful_clients) == 0:
                exit(1)
            else:
                exit(2)


class LabTool(BaseTool):
    @staticmethod
    def modify_initial_args(args):
        if len(args) == 1:
            args.extend(['example', 'help'])
            return
        for i, arg in enumerate(args):
            if i == 0:
                continue
            if arg in ['-h', '--help'] and (i == 1 or args[i - 1].startswith("-")):
                args[i] = 'example'
                args.append('help')
                break

    def arg_parser(self, args):
        self.modify_initial_args(args)
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-D', '--debug', action="store_true", help="Enable debug logs")
        parser.add_argument('-j', '--json', action="store_true", help="Set output type: json")
        parser.add_argument('-y', action="store_true", help="Confirm all interactive questions")
        self.add_name_cmd_arguments(parser)
        self.parser_help = f"{parser.format_help()}\n\nAvailable methods:\n"
        parsed_args = parser.parse_args(args[1:])
        if parsed_args.debug:
            args.remove('-D')
        return parsed_args

    @staticmethod
    def get_config(name, **kwargs):
        if name.endswith('txt'):
            tb_path = config.find_lab_tb_list_file(name, extension='txt')
            tb_names = config.load_file(tb_path)
        elif ',' in name:
            tb_names = '\n'.join(name.split(','))
        else:
            tb_names = '\n'.join(config.find_config_file_regex(name))
            if not kwargs.get('skip_confirmation') and not LabTool.confirm_selection(tb_names):
                tb_names = None
        assert tb_names, 'No testbed selected'
        return tb_names

    @staticmethod
    def confirm_selection(locations):
        ans = input(f'Matched the following locations:\n{locations}\nConfirm selection (yes/no): ').strip().lower()

        if ans not in ['yes', 'no', 'y', 'n']:
            print(f'{ans} is not a valid choice, please try again')
            return LabTool.confirm_selection(locations)

        return ans in ['yes', 'y']

    @staticmethod
    def format_output(cmd, response, obj, json_output):
        if cmd in ['help']:
            print(response)
            return
        if not response:
            return
        if json_output:
            json_to_print = json.dumps(response, indent=2)
            print(json_to_print)

        table = []
        for output in response.values():
            for tb in output:
                row = [tb]
                row.extend(output[tb])
                table.append(row)
        table = sorted(table, key=operator.itemgetter(0))
        title = list(response.keys())
        table.insert(0, title)
        print(terminaltables.DoubleTable(table).table)

    def get_tool_help(self, cmd, verbose=True, prefix='', not_callable=False):
        return super().get_tool_help(cmd, verbose, prefix="{0} <lab_name.txt | location_list | regex> {1}",
                                     not_callable=False)


class TestBedTool(BaseTool):
    @staticmethod
    def modify_initial_args(args):
        if len(args) == 1:
            args.append('help')
            return
        for i, arg in enumerate(args):
            if i == 0:
                continue
            if arg in ['-h', '--help'] and (i == 1 or args[i - 1].startswith("-")):
                args[i] = 'help'
                break

    @staticmethod
    def tool_map(tools_list):
        """
        Creates a dictionary map of tools from list, with associated description and usage strings in nested dict
        Args:
            tools_list: (list) - listing of tools available in repo (typically gathered from tools/README.md)

        Returns: (dict) - Key == tool-name

        """
        tools_map = {}
        with open(os.path.join(TOOLS_DIR, 'README.md')) as tr:
            tool_lines = [line.rstrip() for line in tr.readlines()]
        tool = ''
        description = ''
        usage = ''
        check_continuation = False
        # add a dummy tool (sentinel) to be able to handle the last tool within the loop
        tool_lines.append("###")
        for num, line in enumerate(tool_lines):
            if line.startswith("  -"):
                check_continuation = False
            elif line.startswith("- Notes:"):
                check_continuation = False
            if line.startswith("###"):
                if tool:
                    # we are at a start of a tool, push previous one to tools_map
                    # wrap long descriptions (while usage retains line breaks from the file)
                    description = '\n'.join(wrap(description, 61))
                    tools_map[tool] = {'description': description,
                                       'usage': usage}
                    tool = ''
                    description = ''
                    usage = ''
                    check_continuation = False
                if line[line.rindex('#') + 2:] in tools_list:
                    tool = line[line.rindex('#') + 2:]
                continue
            if tool and not usage:
                if line.startswith("- Description:"):
                    description += line[line.index(':') + 2:]
                    check_continuation = True
                    continue
                if line.startswith("- Usage:"):
                    check_continuation = False
                elif description and check_continuation:
                    # continuation of description
                    description += ' ' + line.strip()
                    continue
            if description:
                if line.startswith("- Usage:"):
                    usage += line[line.index(':') + 2:].replace('`', '')
                    check_continuation = True
                    continue
                if usage and check_continuation:
                    # continuation of usage
                    usage += '\n' + line.strip().replace('`', '')
                    continue
        return tools_map

    def limited_tools_per_config(self, tools_list, debug=False):
        """
        Parses the available testbed components, and limits the output tools list if not available for tb location

        Args:
            tools_list: (list[str]) - total list of strings of available repo tools
            debug: (bool) - If set to True - adds explicit logging as available tools removed from output

        Notes:
            tool to config-key mapping:
                - server -> requires 'ssh_gateway'
                - switch -> requires 'Switch'
                - rpower -> requires 'rpower'
                - pod -> requires 'Nodes'
                - client -> requires 'Clients'

        Returns:
            (list): A full tools list if all available for tb, otherwise a stripped down list of capabilities
        """
        try:
            tb_config = self.get_config()
        except Exception as error:
            log.error(f'Failed to get testbed config info -> {error}')
            return tools_list
        tb_keys = [key.lower() for key in tb_config]
        # mapping of tool to list of required configs for tool to be available per TB
        tool_config_map = {
            'server': ['ssh_gateway'],
            'switch': ['switch'],
            'rpower': ['rpower'],
            'pod': ['nodes'],
            'client': ['clients']
        }
        for tool_map in tool_config_map:
            if tool_map not in tools_list:
                continue
            for config_key in tool_config_map[tool_map]:
                if config_key in tb_keys:
                    continue
                if debug:
                    log.info(f'[Debug]: Config key -> "{config_key}" not found for TB, '
                             f'removing tool -> "{tool_map}" from available list')
                tools_list.remove(tool_map)
        return tools_list

    def tb_tools_list(self):
        """
        List of available Testbed tools available in the repo (found in tools directory)

        Args:
            args: (list) - parsed arguments gathered from sys.argv and argparse lib
        """
        tools_whitelist = [
            "pset",
            "reserve",
            "attenuator",
            "client",
            "cloud",
            "log-pull",
            "pod",
            "ptopo",
            "rpower",
            "sanity",
            "server",
            "switch",
            "osrt_snapshot_decoder"
        ]
        tools_whitelist = [tool for tool in tools_whitelist if tool in [
            tool_name for tool_name in os.listdir(TOOLS_DIR) if tool_name not in ['README.md']
        ]]

        if tool_target := os.environ.get('OPENSYNC_TESTBED'):
            tools_whitelist = self.limited_tools_per_config(tools_whitelist, debug=False)
            tool_target = f'testbed {tool_target}'
        else:
            tool_target = 'testbed environment'
            tools_whitelist = ["pset", "reserve"]
        table = [["Tool Name", "Description", "Usage"]]
        tool_mapping = __class__.tool_map(tools_whitelist)
        for tool in tools_whitelist:
            try:
                table.append([tool, tool_mapping[tool]['description'], tool_mapping[tool]['usage']])
            except KeyError as e:
                print(f'Error loading tool ({tool}) description:', e)
        tools_str = f"Command-Line tools available for {tool_target}"
        delim = "=" * len(tools_str) + "=" * 6
        print(f'{delim}\n== {tools_str} ==\n{delim}')
        print(terminaltables.AsciiTable(table).table)

    def arg_parser(self, args):
        self.modify_initial_args(args)
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument('-D', '--debug', action="store_true", help="Enable debug logs")
        parser.add_argument('-j', '--json', action="store_true", help="Set output type: json")
        self.add_cmd_arguments(parser)
        self.parser_help = f"{parser.format_help()}\n\nAvailable methods:\n"
        parsed_args = parser.parse_args(args[1:])
        if parsed_args.debug:
            args.remove('-D')
        return parsed_args

    def get_config(self):
        '''
        If the aforementioned flags not present, testbed location will be gathered from env variable
        If neither semaphores exist - will raise an error and present help message

        Returns: (dict) - dictionary containing testbed deployment specific values
        '''
        if self.tb_config:
            return self.tb_config
        env_location = os.environ.get('OPENSYNC_TESTBED')
        if env_location:
            tb_location = env_location
        elif self.parsed_args.config:
            tb_location = self.parsed_args.config
            if tb_location not in self.tb_choices():
                log.error(f'Testbed location choices are restricted to -> {self.tb_choices()}')
                exit(1)
        else:
            # log.error('Testbed location not specified neither as -c/--config arg nor in "OPENSYNC_TESTBED" env var')
            print(self.parser_help)
            exit(1)
        try:
            self.tb_config = config.load_tb_config(location_file=tb_location, skip_deployment=True)
        except Exception as error:
            print(f"Cannot load config file: {error}")
            exit(1)
        return self.tb_config

    @staticmethod
    def format_output(cmd, response, obj, json_output):
        if cmd in ['help']:
            print(response)
            return
        return response

    def tb_choices(self):
        return [test_bed[:test_bed.index('.')] for test_bed in
                os.listdir(os.path.join(BASE_DIR, 'config/locations'))][1:]

    def get_tool_help(self, cmd, verbose=True, prefix='', not_callable=False):
        return super().get_tool_help(cmd, verbose, prefix="{0} {1}", not_callable=False)
