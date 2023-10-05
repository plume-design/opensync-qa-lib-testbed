import pytest

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.allure_util import MyAllureListener


@pytest.fixture(autouse=True)
def print_test_separator(request):
    def _print_test_method_separator():
        indent = 8
        separator = "~"
        if not hasattr(request.cls, "_item") or not hasattr(request.cls._item, "own_markers"):
            return
        # skip unit tests, which often to not have titles
        if "gen_unit_test" in [mark.name for mark in request.cls._item.own_markers]:
            return
        name = request.cls._item.nodeid if hasattr(request.cls, "_item") else ""
        title = request.cls._get_title(request.cls._item._obj, name)
        log.info(
            f"\n\n{80 * separator}\n" f"{indent * ' '}Test method: \"{title}\"\n" f"{80 * separator}", show_file=False
        )

    def _print_test_case_separator():
        indent = 4
        separator = "#"
        title = _get_title(request.node)
        tr = []
        automatics = ""
        for mark in request.node.all_markers:
            if mark.name == "testrail":
                tr = mark.kwargs.get("ids", [])
            if mark.name.startswith("TC_"):
                automatics = f"{indent * ' '}Automatics: {mark.name}\n"
        tr = f"{indent * ' '}TC ID: {', '.join(tr)}\n" if tr else ""

        log.info(
            f"\n\n{80 * separator}\n"
            f"{indent * ' '}Test case: \"{title}\"\n"
            f"{tr}"
            f"{automatics}"
            f"{80 * separator}",
            show_file=False,
        )

    def _get_title(node) -> str:
        name = "::".join(node.nodeid.split("::")[0:2]) if hasattr(node, "nodeid") else ""
        title = MyAllureListener.get_allure_title(node)
        if not title:
            title = f"Missing allure title for test: {name}"
        param_id = " [" + node.callspec.id + "]" if hasattr(node, "callspec") else ""
        return title + param_id

    if hasattr(request, "cls") and request.cls:
        # class based approach test method separator printer
        _print_test_method_separator()
    else:
        # allure.step approach test case separator printer
        _print_test_case_separator()
