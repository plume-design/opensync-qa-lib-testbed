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

### reserve

- Description: Tool for test bed reservation. '.' is used to indicate current
  test bed picked by pset. SSH timeout is set to 5 sec.
- Usage: `reserve {<tb_name>[,...] | . | tb* | all} {<cmd>|help} [args]`
  - (use `reserve -h` to list available commands)
- Notes:
  - With -f/--force you can force reservation/unreserve

### attenuator

- Description: Tool for manipulation of attenuation settings
- Usage: `attenuator {<cmd>|help} [args]`
  - (use `attenuator -h` to list available commands)

### client

- Description: Tool for interacting with testbed client devices
- Usage: `client {<client_name>[,...] | all} {<cmd>|help} [args]`
  - (use `client -h` to list available commands)

### log-pull

- Description: Trigger log-pull and pull logs for location or testbed
- Usage: `log-pull [options]`
  - (use `log-pull -h` to list available commands)

### pod

- Description: Tool for interacting with testbed pods
- Usage: `pod {<pod_name>[,...] | all} {<cmd>|help} [args]`
  - (use `pod -h` to list available commands)

### ptopo

- Description: Tool for retrieving location topology in JSON format
- Usage: `ptopo {<cmd>|help}`
  - (use `ptopo -h` to list available commands)

### rpower

- Description: Tool for interacting with testbed remote PDU device
- Usage: `rpower {<device_name>[,...] | all | pods | clients} {<cmd>|help} [args]`
  - (use `rpower -h` to list available commands)

### sanity

- Description: Perform sanity check on a specific directory
- Usage: `sanity [--dir DIR] [--file FILE] [--simple-out]`
  - (use `sanity -h` to list available commands)

### server

- Description: Tool for interacting with testbed rpi-server
- Usage: `server {<cmd>|help} [args]`
  - (use `server -h` to list available commands)

### switch

- Description: Tool for interacting with testbed switch
- Usage: `switch {<cmd>|help} [args]`
  - (use `switch -h` to list available commands)
