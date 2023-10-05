#!/usr/bin/env python

import re
import json
from collections import defaultdict
from lib_testbed.generic.util.logger import log


def ovsdb_decode_value(col):
    if type(col) is not list:
        return col
    if col[0] == "uuid":
        return col[1]

    elif col[0] == "set":
        if len(col[1]) == 0:
            return ""
        a = []
        for val in col[1]:
            a.append(ovsdb_decode_value(val))
        return a

    elif col[0] == "map":
        aa = {}
        for val2 in col[1]:
            aa[val2[0]] = ovsdb_decode_value(val2[1])
        return aa
    else:
        return


def ovsdb_decode_row(row, table_headings):
    tent = defaultdict(list)
    index = 0
    for val in row:
        tent[table_headings[index]] = ovsdb_decode_value(val)
        index = index + 1

    return tent


def ovsdb_decode_table(json_dump):
    try:
        ovsdb_table = json.loads(json_dump)
    except:
        log.error(f"Can not decode {json_dump} as JSON")
        return None
    table_name = ovsdb_table["caption"]
    table_headings = ovsdb_table["headings"]
    table = []
    for row in ovsdb_table["data"]:
        table.append(ovsdb_decode_row(row, table_headings))
    ret = {}

    if "time" in ovsdb_table["data"]:
        ret["time"] = ovsdb_table["time"]

    ret[table_name] = table
    return ret


def ovsdb_decode(json_dump):
    tables = {}
    for line in json_dump:
        line = line.strip(" ")
        line = line.strip("\t")
        line = line.strip("\n")
        if line == "":
            continue
        table = ovsdb_decode_table(line)
        if table:
            tables.update(table)
    return tables


def ovsdb_find_row(table, key, val):
    for row in table:
        if key in row:
            if isinstance(row[key], list):
                if val in row[key]:
                    return row
            elif isinstance(val, dict):
                if val == row[key]:
                    return row
            elif isinstance(val, int):
                if val == row[key]:
                    return row
            elif re.fullmatch(val, row[key]):
                return row
            elif isinstance(val, str) and isinstance(row[key], str) and val.lower() == row[key].lower():
                return row
    return None


def ovsdb_get_key_values(table, key):
    ret = []
    for row in table:
        if key in row:
            ret.append(row[key])
    return ret
