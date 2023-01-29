import importlib
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.object_factory import ObjectFactory


class Switch(ObjectFactory):

    def resolve_obj(self, **kwargs):
        config = kwargs.get("config")
        if not config:
            raise Exception(f"Missing config in kwargs: {kwargs}")
        module_name = "switch_api_resolver"
        class_name = "SwitchApiResolver"
        kwargs = {"config": config}
        module_path = ".".join(["lib_testbed", "generic", "switch", module_name])
        try:
            module = importlib.import_module(module_path)
            _class = getattr(module, class_name)
            log.debug(f"Calling {module_path}.{class_name}")
            return _class(**kwargs)
        except ImportError:
            raise Exception(f"Class: {class_name} not implemented, expected path: {module_path}.py")

    def create_obj(self, module_name, **kwargs):
        kwargs.update({'name': 'api'})
        return super().create_obj(module_name, **kwargs)
