import re
import importlib


class SwitchApiResolver:
    def __init__(self, config):
        self.tb_config = config
        self.switch_api_objects = self.init_switch_api_objects()

    def init_switch_api_objects(self):
        switch_api_objects = list()
        for switch_unit in self.tb_config["Switch"]:
            switch_api_obj = self.get_switch_api(switch_unit["type"])(
                config=self.tb_config, switch_unit_cfg=switch_unit
            )
            switch_api_objects.append(switch_api_obj)
        return switch_api_objects

    @staticmethod
    def get_switch_api(switch_type):
        module_path = ".".join(["lib_testbed", "generic", "switch", switch_type, "switch_api"])
        r = re.compile(".*SwitchApi", re.IGNORECASE)
        module = importlib.import_module(module_path)
        class_name = list(filter(r.match, dir(module)))
        if not class_name:
            raise Exception(f"Not found library for {switch_type} switch type")
        class_name = class_name[0]
        return getattr(module, class_name)

    def __getattr__(self, attr_name):
        return SwitchApiResolver.getattr(obj_list=self.switch_api_objects, attr_name=attr_name)

    @classmethod
    def getattr(cls, obj_list, attr_name):
        def hooked(*args, **kwargs):
            responses = []
            not_callable = kwargs.pop("not_callable", False)
            for obj in obj_list:
                attr = obj.__getattribute__(attr_name)
                if not_callable:
                    response = attr
                else:
                    response = attr(*args, **kwargs)
                responses.append(response)
            return SwitchApiResolver.parse_responses(obj_list=obj_list, responses=responses)

        if not obj_list:
            raise Exception("Switch objects not available")

        try:
            attr = obj_list[0].__getattribute__(attr_name)
        except AttributeError as err:
            raise AttributeError(err)

        if callable(attr):
            return hooked
        else:
            return hooked(not_callable=True)

    @staticmethod
    def parse_responses(obj_list, responses):
        if len(obj_list) == 1:
            return responses[0]
        responses = [response for response in responses if response or isinstance(response, bool)]
        if len(responses) == 1:
            return responses[0]
        return responses
