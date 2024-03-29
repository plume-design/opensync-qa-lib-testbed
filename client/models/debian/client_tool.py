from lib_testbed.generic.client.models.generic.client_tool import ClientTool as ClientToolGeneric


class ClientTool(ClientToolGeneric):
    def upgrade(
        self,
        fw_path=None,
        restore_cfg=True,
        force=False,
        http_address="",
        download_locally=True,
        version=None,
        restore_files=None,
        **kwargs,
    ):
        """
        Upgrade device with FW from fw_path or download build version from the artifactory

        You can also pick FW version based on the latest or stable release.
        """
        if not isinstance(restore_cfg, bool):
            restore_cfg = eval(restore_cfg)
        if not isinstance(force, bool):
            force = eval(force)
        if not isinstance(download_locally, bool):
            download_locally = eval(download_locally)
        results = self.lib.upgrade(
            fw_path, restore_cfg, force, http_address, download_locally, version, restore_files, **kwargs
        )
        return results
