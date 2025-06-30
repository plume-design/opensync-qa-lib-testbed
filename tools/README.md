# qa-lib-testbed/tools

- Available CLI tools for working w/ testbeds

## Tools list

### pset

- Description: Display or activate configured testbeds (most tools depend on
  pset having been initialized against a testbed)
- Usage: `pset [<tb_name>]`
- Notes:
  - `pset` without args will display configured testbeds from files located in
    `config/locations`

### osrt

- Description: Entry point to access all osrt tools: reserve, server, client, pod, etc.
- Usage: `osrt [tool] [command]`.
  - (use `osrt -h`, `osrt [tool] -h` and `osrt [tool] [command] -h` to list commands and get detailed help)

