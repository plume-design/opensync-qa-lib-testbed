from lib_testbed.generic.pod.qca.pod_lib import PodLib as PodLibGeneric
from lib_testbed.generic.pod.generic.pod_lib import DFS_REGION_MAP


class PodLib(PodLibGeneric):

    def get_partition_dump(self, partition, **kwargs):
        """
        Get partition hex dump
        Args:
            partition: (str) partition name
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        dump = ''
        part = 'BOOTCFG2' if 'rootfs2' in partition else 'BOOTCFG1'
        mtd = self.get_stdout(self.strip_stdout_result(
            self.run_command(f'cat /proc/mtd | grep {part} | sed "s/:.*//"')), **kwargs)
        hexdump = self.run_command(f'hexdump /dev/{mtd}')
        for line in hexdump[1].splitlines():
            if line.startswith('*'):
                continue
            # big/little indian convert
            for part in line.split():
                if len(part) > 4:
                    continue
                dump += part[2:] + part[:2] + ' '
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
        assert rgm in self.run_command("pmf -r -rgdmn1", **kwargs)[1], 'Different regions for radio0 and radio1'
        assert rgm in self.run_command("pmf -r -rgdmn2", **kwargs)[1], 'Different regions for radio0 and radio2'
        for region in DFS_REGION_MAP:
            if DFS_REGION_MAP[region].lower() == rgm:
                return [0, region, '']
        return [1, '', f'Cannot find proper region in DFS_REGION_MAP for {rgm}']
