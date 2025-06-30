from lib_testbed.generic.util.logger import log
from typing import Literal

CHANNEL_GROUPS = {
    "5G": {
        "40": [
            [36, 40],
            [44, 48],
            [52, 56],
            [60, 64],
            [100, 104],
            [108, 112],
            [116, 120],
            [124, 128],
            [132, 136],
            [140, 144],
            [149, 153],
            [157, 161],
        ],
        "80": [
            [36, 40, 44, 48],
            [52, 56, 60, 64],
            [100, 104, 108, 112],
            [116, 120, 124, 128],
            [132, 136, 140, 144],
            [149, 153, 157, 161],
        ],
        "160": [
            [36, 40, 44, 48, 52, 56, 60, 64],
            [100, 104, 108, 112, 116, 120, 124, 128],
        ],
    },
    "6G": {
        "40": [
            [1, 5],
            [9, 13],
            [17, 21],
            [25, 29],
            [33, 37],
            [41, 45],
            [49, 53],
            [57, 61],
            [65, 69],
            [73, 77],
            [81, 85],
            [89, 93],
            [97, 101],
            [105, 109],
            [113, 117],
            [121, 125],
            [129, 133],
            [137, 141],
            [145, 149],
            [153, 157],
            [161, 165],
            [169, 173],
            [177, 181],
            [185, 189],
            [193, 197],
            [201, 205],
            [209, 213],
            [217, 221],
            [225, 229],
        ],
        "80": [
            [1, 5, 9, 13],
            [17, 21, 25, 29],
            [33, 37, 41, 45],
            [49, 53, 57, 61],
            [65, 69, 73, 77],
            [81, 85, 89, 93],
            [97, 101, 105, 109],
            [113, 117, 121, 125],
            [129, 133, 137, 141],
            [145, 149, 153, 157],
            [161, 165, 169, 173],
            [177, 181, 185, 189],
            [193, 197, 201, 205],
            [209, 213, 217, 221],
        ],
        "160": [
            [1, 5, 9, 13, 17, 21, 25, 29],
            [33, 37, 41, 45, 49, 53, 57, 61],
            [65, 69, 73, 77, 81, 85, 89, 93],
            [97, 101, 105, 109, 113, 117, 121, 125],
            [129, 133, 137, 141, 145, 149, 153, 157],
            [161, 165, 169, 173, 177, 181, 185, 189],
            [193, 197, 201, 205, 209, 213, 217, 221],
        ],
        "320": [
            [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61],
            [65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125],
            [129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189],
            [33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93],
            [97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157],
            [161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221],
        ],
    },
}

"""
Region map with supported channels for countries. For each band (2.4G, 5G, 6G) the list contains channel boundaries.
"""
REGION_MAP = {
    "EU": {
        "2.4G": [
            (1, 13),
        ],
        "5G": [(36, 48), (52, 144)],
        "6G": [
            (1, 93),
        ],
    },
    "US": {
        "2.4G": [
            (1, 11),
        ],
        "5G": [(36, 48), (52, 144), (149, 165)],
        "6G": [
            (1, 93),
            (97, 113),
            (117, 185),
            (189, 233),
        ],
    },
    "JP": {
        "2.4G": [
            (1, 13),
        ],
        "5G": [(36, 48), (52, 144)],
        "6G": [
            (1, 93),
        ],
    },
}


def is_channel_allowed_in_region(region: str, band: Literal["2.4G", "5G", "6G"], channel: int) -> bool:
    """
    Determines whether a given wireless channel is supported for a specific region and band.

    This function evaluates the compatibility of a specific region, band, and wireless channel. Based on these inputs,
    it determines if the provided configuration is valid and allowed under applicable rules or restrictions.

    Args:
        region: The geographical region for which the wireless channel is being evaluated.
        band: The frequency band (e.g., 2.4G , 5G or 6G)
        channel: The wireless channel number

    Returns:
        bool: True if the specified channel is supported for the given region and band, False otherwise.
    """
    region = region.upper()
    if region not in REGION_MAP:
        log.error(f"Region {region} not found in REGION_MAP")
        return False
    if band not in REGION_MAP[region]:
        log.error(f"Band {band} not found in REGION_MAP for region {region}")
        return False

    for lower, upper in REGION_MAP[region][band]:
        if lower <= channel <= upper:
            return True

    return False
