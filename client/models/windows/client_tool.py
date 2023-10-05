from lib_testbed.generic.client.models.generic.client_tool import ClientTool as ClientToolGeneric


class ClientTool(ClientToolGeneric):
    def __init__(self, lib):
        self.lib = lib
