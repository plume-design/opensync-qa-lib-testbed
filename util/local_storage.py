"""This module simply keeps global information. A module was chosen as the simplest implementation
of a singleton.
"""

inv_available = True
"""Property holding the information on whether inventory is available or not."""


node_deployment_cache = {}
"""Dictionary holding map with node id -> deployment name."""
