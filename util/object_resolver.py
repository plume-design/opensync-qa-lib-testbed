import os
import importlib
from pathlib import Path
from lib_testbed.generic.util.common import DeviceCommon

LIB_TESTBED_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', ".."))


class ObjectResolver:

    @staticmethod
    def path_verification(model_paths, model_type):
        verified_paths = list()
        for path in model_paths:
            if not os.path.exists(path):
                continue
            verified_paths.append(path)
        assert verified_paths, f'Model path does not exist: {model_paths} for {model_type}'
        return verified_paths[0]

    @staticmethod
    def resolve_model_path_class(file_path, file_name):
        base_dir = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..'))
        path_relative = file_path.replace(base_dir + '/', '')
        class_name = ''.join(x.capitalize() or '_' for x in file_name.split('.')[0].split('_'))
        module_name = path_relative.replace('/', '.').rstrip('.py')
        lib_module = importlib.import_module(module_name)
        return getattr(lib_module, class_name)

    # CLIENT SECTION
    @staticmethod
    def resolve_client_class(file_name, model, directory_type='generic'):
        model = DeviceCommon.convert_model_name(model)
        client_dir_path = ObjectResolver.get_client_dir_path(model=model, directory_type=directory_type)
        client_path_file = ObjectResolver.get_client_path_file(model_path=client_dir_path, file_name=file_name)
        return ObjectResolver.resolve_model_path_class(file_path=client_path_file, file_name=file_name)

    @staticmethod
    def get_client_dir_path(model, directory_type):
        device_path = os.path.join(LIB_TESTBED_DIR, directory_type, 'client')
        model_paths = []
        for file_path in Path(device_path).glob(f'**/models/{model}'):
            model_paths.append(os.fsdecode(file_path))
        if not model_paths:
            # Get generic path
            model_paths.append(os.path.join(device_path, 'models', 'generic'))
        return ObjectResolver.path_verification(model_paths=model_paths, model_type=model)

    @staticmethod
    def get_client_path_file(model_path, file_name):
        path = None
        # Search for lib directory
        for file_path in Path(model_path).glob(f'**/{file_name}'):
            path = os.fsdecode(file_path)
            break
        if not path:
            # Try to find generic library
            model_path = os.path.dirname(model_path)
            for file_path in Path(model_path).glob(f'**/generic/**/{file_name}'):
                path = os.fsdecode(file_path)
                break
        if not path:
            raise KeyError(f'Could not resolve path for file: {file_name} in {model_path}')
        return path

    # POD SECTION
    @staticmethod
    def get_wifi_vendor(model):
        from lib_testbed.generic.util.config import get_model_capabilities
        return get_model_capabilities(model)['wifi_vendor']

    @staticmethod
    def resolve_pod_class(file_name, model, wifi_vendor=None):
        pod_path_file = ObjectResolver.resolve_model_path_file(file_name=file_name, model=model, wifi_vendor=wifi_vendor)
        return ObjectResolver.resolve_model_path_class(file_path=pod_path_file, file_name=file_name)

    @staticmethod
    def resolve_model_path_file(file_name, model, wifi_vendor=None):
        model = DeviceCommon.convert_model_name(model)
        if not wifi_vendor:
            wifi_vendor = ObjectResolver.get_wifi_vendor(model)
        pod_dir_paths = ObjectResolver.get_pod_dir_paths(model=model, wifi_vendor=wifi_vendor)
        return ObjectResolver.get_pod_path_file(pod_dir_paths=pod_dir_paths, file_name=file_name, model=model)

    @staticmethod
    def get_pod_dir_paths(model, wifi_vendor=None):
        model = DeviceCommon.convert_model_name(model)
        if not wifi_vendor:
            wifi_vendor = ObjectResolver.get_wifi_vendor(model)
        pod_dir_paths = list()
        # Try to find specific model path
        for pod_dir_path in Path(LIB_TESTBED_DIR).glob(f'**/{model}'):
            pod_dir_paths.append(os.fsdecode(pod_dir_path))
        # Add generic vendor path
        pod_dir_paths.append(os.path.join(LIB_TESTBED_DIR, 'generic', 'pod', wifi_vendor))
        # Add generic path
        pod_dir_paths.append(os.path.join(LIB_TESTBED_DIR, 'generic', 'pod', 'generic'))
        return pod_dir_paths

    @staticmethod
    def get_pod_path_file(pod_dir_paths, file_name, model):
        expected_file_path = None
        for pod_dir_path in pod_dir_paths:
            for file_path in Path(pod_dir_path).glob(file_name):
                expected_file_path = os.fsdecode(file_path)
                break
            if expected_file_path:
                break
        assert expected_file_path, f'Could not resolve path for file: {file_name} and model: {model}'
        return expected_file_path
