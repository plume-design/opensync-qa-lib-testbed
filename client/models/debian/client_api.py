from lib_testbed.generic.client.models.generic.client_api import ClientApi as ClientApiGeneric


class ClientApi(ClientApiGeneric):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

