
import enum
import ipaddress


class WAN_VLAN(enum.IntEnum):
    """
    Describes a testbed WAN VLAN

    Attributes:
        value (int): VLAN ID of the testbed WAN network
        name (str): Name of the testbed WAN network
        ipv4_subnet (IPv4Network): IPv4 subnet used on this WAN VLAN, or '0.0.0.0/32' if not used
        ipv4_gateway (IPv4Address): IPv4 address of default gateway, or '0.0.0.0' if not used
        ipv4_nameserver (IPv4Address): IPv4 address of DNS name server, or '0.0.0.0' if not used
        ipv6_subnet (IPv6Network): IPv6 subnet used on this WAN VLAN, or '::/128' if not used
        ipv6_gateway (IPv6Address): IPv6 address of default gateway, or '::' if not used
        ipv6_nameserver (IPv6Address): IPv6 address of DNS name server, or '::' if not used
        ipv6_delegated (IPv6Network): IPv6 subnet from which prefixes are delegated on this WAN VLAN.
                                      Same as ipv6_subnet when prefix delegation is not in use.
        wano_config (dict): WAN Orchestrator settings needed to connect to this network
        tagged_wano_config (dict): WANO settings needed when this network is delivered as tagged VLAN
    """

    IPv4 =                200, "192.168.200.0/24", "::/128",                  "::/128"                   # noqa: E222, E241, E501
    IPv6_STATEFUL =       201, "192.168.201.0/24", "2001:ee2:1704:9901::/64", "2001:ee2:1704:99e0::/59"  # noqa: E222, E241, E501
    IPv6_STATELESS =      202, "192.168.202.0/24", "2001:ee2:1704:9902::/64", "2001:ee2:1704:9902::/64"  # noqa: E222, E241, E501
    IPv6_SLAAC =          203, "192.168.203.0/24", "2001:ee2:1704:9903::/64", "2001:ee2:1704:9903::/64"  # noqa: E222, E241, E501
    IPv6_ONLY_STATEFUL =  204, "0.0.0.0/32",       "2001:ee2:1704:9904::/64", "2001:ee2:1704:99c0::/59"  # noqa: E222, E241, E501
    IPv6_ONLY_STATELESS = 205, "0.0.0.0/32",       "2001:ee2:1704:9905::/64", "2001:ee2:1704:9905::/64"  # noqa: E222, E241, E501
    IPv6_ONLY_SLAAC =     206, "0.0.0.0/32",       "2001:ee2:1704:9906::/64", "2001:ee2:1704:9906::/64"  # noqa: E222, E241, E501
    IPTV_BRIDGED =        207, "192.168.207.0/24", "2001:ee2:1704:9907::/64", "2001:ee2:1704:99a0::/60"  # noqa: E222, E241, E501
    IPTV_ROUTED =         208, "192.168.208.0/24", "2001:ee2:1704:9908::/64", "2001:ee2:1704:99b0::/60"  # noqa: E222, E241, E501
    IPv4_PUBLIC =         210, "99.99.210.0/24",   "::/128",                  "::/128"                   # noqa: E222, E241, E501
    IPv4_STATIC =         220, "192.168.220.0/24", "::/128",                  "::/128"                   # noqa: E222, E241, E501
    IPv4_PPPoE_CHAP =     230, "192.168.230.0/24", "::/128",                  "::/128"                   # noqa: E222, E241, E501
    IPv4_PPPoE_PAP =      231, "192.168.231.0/24", "::/128",                  "::/128"                   # noqa: E222, E241, E501
    IPv6_PPPoE_CHAP =     232, "192.168.232.0/24", "2001:ee2:1704:9932::/64", "2001:ee2:1704:9932::/64"  # noqa: E222, E241, E501
    IPv6_PPPoE_PAP =      233, "192.168.233.0/24", "2001:ee2:1704:9933::/64", "2001:ee2:1704:9933::/64"  # noqa: E222, E241, E501
    MAX_VLAN =           4094, "192.168.94.0/24",  "::/128",                  "::/128"                   # noqa: E222, E241, E501

    def __new__(cls, value, ipv4_subnet, ipv6_subnet, ipv6_delegated):
        # super() or enum.IntEnum.__new__() can't be used for some obscure Enum specific reason
        self = int.__new__(cls, value)
        self._value_ = value
        self.ipv4_subnet = ipaddress.IPv4Network(ipv4_subnet)
        self.ipv6_subnet = ipaddress.IPv6Network(ipv6_subnet)
        self.ipv6_delegated = ipaddress.IPv6Network(ipv6_delegated)
        self.ipv4_gateway = self.ipv4_nameserver = next(iter(self.ipv4_subnet.hosts()))
        self.ipv6_gateway = self.ipv6_nameserver = next(iter(self.ipv6_subnet.hosts()))
        return self

    @property
    def wano_config(self):
        config = {'wanConnectionType': 'dynamic'}
        if "PPPoE" in self.name:
            config["PPPoE"] = {"enabled": True}
            if "CHAP" in self.name:
                config["PPPoE"]["username"] = "plumechap"
                config["PPPoE"]["password"] = "12testchap"
            elif "PAP" in self.name:
                config["PPPoE"]["username"] = "plumepap"
                config["PPPoE"]["password"] = "12testpap"
        elif self.name == "IPv4_STATIC":
            config["staticIPv4"] = {
                "enabled": True,
                "ip": "192.168.220.42",
                "gateway": "192.168.220.1",
                "subnet": "255.255.255.0",      # Misspelt netmask is by the spec
                "primaryDns": "8.8.8.8",
                "secondaryDns": "8.8.8.4"
            }
        return config

    @property
    def tagged_wano_config(self):
        config = self.wano_config
        config["DataService"] = {
            "enabled": True,
            "VLAN": self.value,
            "QoS": 0,
        }
        return config
