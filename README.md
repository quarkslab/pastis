# README

## Installation

```bash
python ./setup.py {develop,install}
```

## Examples

**NOTE** Use the following Honggfuzz version: [`2.1/pastis/master`](https://gitlab.qb/pastis/honggfuzz/-/tree/2.1/pastis/master).

### Running it as `FileAgent` (aka offline mode)

1. Set environment variables:

```bash
export HFUZZ_PATH=</path/to/honggfuzz>
export HFUZZ_WS=</path/to/workspace>    # for instance, /tmp/hfuzz-workspace.
```

2. Run:

```bash
./scripts/honggfuzz-explore.py \
    --target ../programme_etalon_final/micro_http_server/micro_http_server_hf_fuzz_single_without_vuln \
    --target-arguments "wlp0s20f3 48:e2:44:f5:9b:01 10.0.13.86 255.255.255.0 10.0.13.254"
```

### Running it as `ClientAgent`

1. Set environment variables:

```bash
export HFUZZ_PATH=</path/to/honggfuzz>
export HFUZZ_WS=</path/to/workspace>    # for instance, /tmp/hfuzz-workspace.
```

2. Run Broker:

```bash
./examples/broker-agent.py \
    --target ../programme_etalon_final/micro_http_server/micro_http_server_hf_fuzz_single_without_vuln \
    --target-arguments "wlp0s20f3 48:e2:44:f5:9b:01 10.0.13.86 255.255.255.0 10.0.13.254"
```

3. Run Client:

```bash
./examples/honggfuzz-agent.py
```
