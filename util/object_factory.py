import os
import re
import json
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.config import load_tb_config


class ObjectFactory(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def create_obj(self, module_name, **kwargs):
        name = kwargs.pop("name", None)
        if not name:
            name = kwargs.get("role")
            if not name:
                if kwargs.get('config'):
                    # skip printing massive config info
                    del kwargs['config']
                raise Exception(f"Missing 'name' or 'role' in opensync_ mark: {kwargs}")
        if hasattr(self, name):
            raise Exception(f"Name conflict, object self.{name} already exists")
        kwargs['role_prefix'] = name
        obj = self.resolve_obj(**kwargs)
        setattr(self, name, obj)
        obj.obj_name = {'name': name, 'module_name': module_name}
        if hasattr(obj, 'obj_list'):
            # set object name for listed objects - case for init object by the pods, clients marks
            for obj_from_list in obj.obj_list:
                obj_from_list.obj_name = obj.obj_name
        return obj

    @staticmethod
    def update_config_with_motion_cred(config):
        if not config:
            return
        dpl = config.get('deployment_id')
        if dpl and dpl in ['beta', 'chi', 'chi-staging', 'delta', 'gamma', 'kappa', 'sigma', 'tau-int', 'tau-prod',
                           'theta', 'dog1']:
            cred_file = f'{os.environ["HOME"]}/automation/resources/creds/motion{dpl}.json'
            if not os.path.exists(cred_file):
                return
            try:
                with open(cred_file) as cred:
                    info = json.load(cred)
                    config.update(info)
                    return
            except IOError:
                pass

    @staticmethod
    def get_class_name(module, module_name):
        module_name = module_name.split('.')[-1]
        module_name = module_name.replace('_', '')
        r = re.compile(f".*{module_name}", re.IGNORECASE)
        class_name = list(filter(r.match, dir(module)))
        if not class_name:
            raise Exception(f'Can not dynamically get class name for "{module_name}" module name')
        return class_name[0]


class PyMoveToDeploymentPlugin:
    import pytest

    @pytest.fixture(scope="session", autouse=True)
    def move_to_deployment_fixture(self, request):
        # Unit tests intentionally leave tb_config unset, because they are not allowed
        # to touch the actual testbed. So also skip migrating the testbed to a different
        # deployment when running unit tests.
        if getattr(request.config.option, "tb_config", None) is None:
            return
        # move and reload whole config
        cfg = self.move_to_deployment(request.config.option.tb_config, self.config_name)
        if not cfg:
            return
        request.config.option.tb_config = cfg
        for item in request.session.items:
            item.cls.tb_config = cfg
            item.cls.tb_config_orig = cfg

    def __init__(self, config_name, deployment):
        self.config_name = config_name
        self.deployment = deployment

    def move_to_deployment(self, tb_config, config_name):
        loc_deployment = tb_config['profile']
        if loc_deployment != self.deployment:
            try:
                from lib.util.plumetoollib import PlumeToolLib
            except ModuleNotFoundError:
                raise OpenSyncException("Required PlumeToolLib is missing", "Add plumetoollib module")
            log.info(f'Moving location from "{loc_deployment}" to "{self.deployment}" deployment')
            kwargs = {"config": tb_config}
            plumelib = PlumeToolLib(**kwargs)
            if plumelib.move_to_deployment(self.deployment):
                log.info(f'Location has been moved successfully to {self.deployment}')
            else:
                raise Exception(f'Location has not been moved to {self.deployment}')
            return load_tb_config(config_name)
