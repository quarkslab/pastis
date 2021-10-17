# README

## Installation

```bash
python ./setup.py {develop,install}
```

### Running it as `FileAgent` (aka offline mode)

1. Set environment variables:

```bash
export AFL_PATH=</path/to/afl-fuzz>
export AFL_WS=</path/to/workspace>    # default is /dev/shm/afl_workspace
```

2. Run:

```bash
./scripts/afl-explore.py \
    --target ../programme_etalon_final/micro_http_server/micro_http_server_hf_fuzz_single_without_vuln \
    --target-arguments "wlp0s20f3 48:e2:44:f5:9b:01 10.0.13.86 255.255.255.0 10.0.13.254"
```

### Running it as `ClientAgent`

1. Set environment variables:

```bash
export AFL_PATH=</path/to/afl-fuzz>
export AFL_WS=</path/to/workspace>    # default is /dev/shm/afl_workspace
```

2. Run Broker:

```bash
pastis-broker [ARGS]
```

3. Run Client:

```bash
pastis-afl online
```
