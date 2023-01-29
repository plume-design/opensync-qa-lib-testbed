#!/usr/bin/env python3
import json
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.object_resolver import ObjectResolver


# TODO: Rename function to get_fw_with_rounds() and change all calls to this function
def get_fw(models, version='latest'):
    """
    Args:
        models: (list) models to check
        version: (str) first or latest

    Returns: (tuple) {model: fw}, int() rounds

    """
    latest_fw = {}
    rounds = []
    for model in models:
        fw_dict = load_test_fw_file(model=model)
        if not fw_dict:
            continue
        latest_fw[model] = fw_dict[f'{version}_released_fw']
        rounds.append(fw_dict['rounds'])
        # in case model does not specify its version cancel whole upgrade
        if latest_fw[model] is None:
            log.warning(f'Cannot get {version}_released_fw for {model}. Skipping it')
            return None, 0
    return latest_fw, max(rounds)


def get_fw_model_map(models: list, fw_type: str) -> dict:
    """
    Get firmware model map
    Args:
        models: (list) List of models
        fw_type: (str) FW type specified in test_fw_version.json file

    Returns: (dict) {model: fw_type}

    """
    fw_model_map = dict()
    for model in models:
        fw_dict = load_test_fw_file(model=model)
        if not fw_dict:
            continue
        expected_fw = fw_dict.get(fw_type)
        if not expected_fw:
            log.warning(f'Cannot get {fw_type} firmware for {model}. Skipping it')
            continue
        fw_model_map[model] = expected_fw
    assert fw_model_map, f'Not found any FW for fw type: {fw_type} and models: {models}'
    return fw_model_map


def load_test_fw_file(model):
    fw_dict = None
    try:
        fw_file = ObjectResolver.resolve_model_path_file(file_name='test_fw_version.json', model=model)
        with open(fw_file) as fw:
            fw_dict = json.load(fw)
    except Exception as err:
        log.error(err)
        log.info(f'Upgrading {model} is not supported')
    return fw_dict


def get_latest_released_fw(models):
    return get_fw(models, 'latest')


def get_first_released_fw(models):
    return get_fw(models, 'first')


def get_monitoring_fw(models):
    return get_fw(models, 'monitoring')


def get_ga_fw(models):
    return get_fw(models, 'ga')


def get_capabilities_fw(models):
    return get_fw(models, 'capabilities')


def get_ipv6_capable_and_downloadable_fw(models):
    return get_fw(models, 'ipv6')
