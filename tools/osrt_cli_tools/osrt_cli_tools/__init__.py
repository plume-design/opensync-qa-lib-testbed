"""Python package with new click-based osrt commandline tools."""

# IMPORTANT NOTE on bash autocomplete:
# Python imports take a long time. Really long time.
# Importing many modules takes as long as 1 second on a modern-day machine.
# Therefore, modules are often lazy-loaded, so that bash-autocomplete can work reasonably fast.
# Users wouldn't be willing to wait 1 seconds for every tab-complete hint.

# Aside from that the module tb_config_parser contains a mechanism of caching the list of
# available testbeds and testbed config - all stored in the framework cache directory in
# the marshal format. Marshal was chosen due to its speed.
