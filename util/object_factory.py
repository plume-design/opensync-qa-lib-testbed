import re


class ObjectFactory(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def create_obj(self, module_name, request, **kwargs):
        name = kwargs.pop("name", None)
        if not name:
            name = kwargs.get("role")
            if not name:
                if kwargs.get("config"):
                    # skip printing massive config info
                    del kwargs["config"]
                raise Exception(f"Missing 'name' or 'role' in opensync_ mark: {kwargs}")
        if hasattr(self, name):
            raise Exception(f"Name conflict, object self.{name} already exists")
        kwargs["role_prefix"] = name

        match module_name:
            case "pod":
                obj = self.resolve_obj_by_fixture(request=request, **kwargs)
            case "pods":
                obj = self.resolve_obj_by_fixture(request=request, **kwargs)
            case "client":
                obj = self.resolve_obj_by_fixture(request=request, **kwargs)
            case "clients":
                obj = self.resolve_obj_by_fixture(request=request, **kwargs)
            case _:
                obj = self.resolve_obj(**kwargs)

        setattr(self, name, obj)
        obj.obj_name = {"name": name, "module_name": module_name}
        if hasattr(obj, "obj_list"):
            # set object name for listed objects - case for init object by the pods, clients marks
            for obj_from_list in obj.obj_list:
                # The same object can be shared between two modules. E.g. pod and pods
                if hasattr(obj_from_list, "obj_name") or hasattr(obj_from_list, "obj_names"):
                    self.set_obj_names(obj_from_list, obj.obj_name)
                else:
                    obj_from_list.obj_name = obj.obj_name
        return obj

    @staticmethod
    def get_class_name(module, module_name):
        module_name = module_name.split(".")[-1]
        module_name = module_name.replace("_", "")
        r = re.compile(f".*{module_name}", re.IGNORECASE)
        class_name = list(filter(r.match, dir(module)))
        if not class_name:
            raise Exception(f'Can not dynamically get class name for "{module_name}" module name')
        return class_name[0]

    @staticmethod
    def set_obj_names(obj_from_list, obj_name_to_set):
        if not hasattr(obj_from_list, "obj_names"):
            obj_from_list.obj_names = [obj_from_list.obj_name]
            del obj_from_list.obj_name
        obj_from_list.obj_names.append(obj_name_to_set)
