NEW_RPOWER_PATH = "/tools/rpower"
OLD_RPOWER_PATH = "/home/plume/tools/rpower"


def get_rpower_path(server_obj):
    """
    Return absolute path to `rpower` PDU management tool on the `server_obj` testbed server.
    """
    if server_obj.run_raw(f"test -x {NEW_RPOWER_PATH}")[0] == 0:
        return NEW_RPOWER_PATH
    return OLD_RPOWER_PATH
