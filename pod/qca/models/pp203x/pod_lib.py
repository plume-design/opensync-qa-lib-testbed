from lib_testbed.generic.pod.qca.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):
    def get_partition_dump(self, partition, **kwargs):
        """
        Get partition hex dump
        Args:
            partition: (str) partition name
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        dump = ""
        part = "BOOTCFG2" if "rootfs2" in partition else "BOOTCFG1"
        mtd = self.get_stdout(
            self.strip_stdout_result(self.run_command(f'cat /proc/mtd | grep {part} | sed "s/:.*//"')), **kwargs
        )
        hexdump = self.run_command(f"hexdump /dev/{mtd}")
        for line in hexdump[1].splitlines():
            if line.startswith("*"):
                continue
            # big/little indian convert
            for part in line.split():
                if len(part) > 4:
                    continue
                dump += part[2:] + part[:2] + " "
        hexdump[1] = dump
        return hexdump

    def get_region(self, **kwargs):
        """
        Get pod region from pmf
        Args:
            **kwargs:

        Returns: Region based on the DFS_REGION_MAP

        """
        rgm = self.run_command("pmf -r -rgdmn0", **kwargs)
        if rgm[0]:
            return rgm
        rgm = rgm[1].split()[-1].lower()
        # check if all radios has the same region set
        assert rgm in self.run_command("pmf -r -rgdmn1", **kwargs)[1], "Different regions for radio0 and radio1"
        assert rgm in self.run_command("pmf -r -rgdmn2", **kwargs)[1], "Different regions for radio0 and radio2"
        for region in self.DFS_REGION_MAP:
            if self.DFS_REGION_MAP[region].lower() == rgm:
                return [0, region, ""]
        return [1, "", f"Cannot find proper region in DFS_REGION_MAP for {rgm}"]

    def check_traffic_acceleration(
        self, ip_address, expected_protocol=6, multicast=False, flow_count=1, flex=False, map_t=False, **kwargs
    ):
        """
        Check traffic was accelerated
        Args:
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            map_t: (bool): True if checking acceleration of MAP-T traffic
            **kwargs:

        Returns: bool()

        """
        # On QSDK 11.00 and newer check for flows in both ECM and SFE
        if self.qsdk_version >= 0x1100:
            ecm_ok = self.check_traffic_acceleration_ecm(
                ip_address,
                expected_protocol=expected_protocol,
                multicast=multicast,
                flow_count=flow_count,
                flex=flex,
                map_t=map_t,
                dumps=3,
                **kwargs,
            )
            if not ecm_ok:
                return False
        return self.check_traffic_acceleration_sfe(
            ip_address,
            expected_protocol=expected_protocol,
            multicast=multicast,
            flow_count=flow_count,
            flex=flex,
            map_t=map_t,
            dumps=3,
            **kwargs,
        )

    def run_traffic_acceleration_monitor(self, samples: int = 5, interval: int = 5, delay: int = 20, **kwargs) -> dict:
        """
        Start making traffic acceleration statistics dumps on the pod in the background
        Args:
            samples: (int) number of statistic dumps
            interval: (int) seconds apart
            delay: (int) seconds after the method is called.
            **kwargs:

        Returns: Return (dict) dict(sfe_dump=dict(dump_file="", pid="")) Acceleration statistics dumps details.

        """
        traffic_acceleration_monitor = dict()
        # On QSDK 11.00 and newer check for flows in both ECM and SFE
        if self.qsdk_version >= 0x1100:
            traffic_acceleration_monitor |= self._run_traffic_acceleration_monitor(
                acc_name="ecm", acc_tool="ecm_dump.sh", samples=samples, interval=interval, delay=delay
            )

        traffic_acceleration_monitor |= self._run_traffic_acceleration_monitor(
            acc_name="sfe", acc_tool="sfe_dump", samples=samples, interval=interval, delay=delay
        )
        return traffic_acceleration_monitor
