"""This module contains utility code to handle pytest request as well as method name
in the ``setup_method_handler()`` and ``teardown_method_handler()``"""

import functools


def parse_request(func):
    """Helper decorator to parse pytest request object. If not available,
    a dummy empty object shaped like the pytest request is injected and
    the argument ``request``. It is intended to be helping with

    .. code-block:: py

        def setup_class_handler(self, request)

    and

    .. code-block:: py

        def setup_method_handler(self, request)


    .. note::

        Note that the argument ``request`` is a mandatory argument
        for all setup and teardown hooks.
    """

    @functools.wraps(func)
    def wrapper(self, request, **kwargs):
        """Wrapper is to be used across all test **classes** for the
        ``setup_class_handler``, ``setup_method_handler``,
        ``teardown_method_handler``, ``teardown_handler`` or any other method
        which requires pytest's request. If the request fixture is not
        available (i.e. invoked from outside another fixture or test
        function/method), then this decorator injects an empty dummy
        request.l"""
        if not request:
            if hasattr(self, "request"):
                request = self.request
            else:
                # when available, we just pass the original request object here
                class DummyMagicOption:
                    """Simulates an empty :py:class:`argparse.Namespace`
                    instance, with absolutely all options set to
                    :py:class:`None`. It is used as a stub for
                    pytest's :py:attr:`pytest.request.config.option`
                    and :py:attr:`pytest.request.node.confing.option`
                    attributes."""

                    def __getattr__(self, item):
                        return None

                    def __iter__(self):
                        return self

                    def __next__(self):
                        raise StopIteration

                class DummyConfig:
                    option = DummyMagicOption()

                    def __bool__(self):
                        return False

                class DummyNode:
                    """Stubs pytest's :py:attr:`request.node` with
                    dummy empty config and "Unknown" node name."""

                    config = DummyConfig()
                    originalname = "Unknown"

                class DummyRequest:
                    """Stubs pytest's request object with dummy empty
                    config and test name."""

                    def __init__(self, node, config=None):
                        if not node:
                            node = DummyNode()
                        self.node = node
                        if config:
                            self.node.config = config
                        self.config = self.node.config

                if hasattr(self, "session_config"):
                    request = DummyRequest(
                        node=self.base_session["item"] if hasattr(self, "base_session") else None,
                        config=self.session_confing,
                    )

        return func(self, request=request, **kwargs)

    return wrapper
