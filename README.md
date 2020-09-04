# README

## Installation

```bash
python ./setup.py {develop,install}
```

## Examples

**TODO** Add the Honggfuzz branch that is needed to run the examples.

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
    --target-arguments "wlp0s20f3 5c:80:b6:96:d7:3c 192.168.43.127 255.255.255.0 192.168.43.255"
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
    --target-arguments "wlp0s20f3 5c:80:b6:96:d7:3c 192.168.43.127 255.255.255.0 192.168.43.255"
```

3. Run Client:

```bash
./examples/honggfuzz-agent.py
```
