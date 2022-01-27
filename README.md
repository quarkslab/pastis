# README

## Installation

```bash
pip install .
```

### Running it in offline mode

1. Set environment variables:

```bash
export AFLPP_PATH=</path/to/afl-fuzz>
export AFLPP_WS=</path/to/workspace>    # the default value is /tmp/aflpp_workspace
```

2. Run:

```bash
pastis-afl offline --seed inputs --seedinj STDIN -- <PROGRAMS> <ARGS>
```

### Running it in online mode

1. Set environment variables:

```bash
export AFLPP_PATH=</path/to/afl-fuzz>
export AFLPP_WS=</path/to/workspace>    # the default value is /tmp/aflpp_workspace
```

2. Run Broker:

```bash
pastis-broker [ARGS]
```

3. Run Client:

```bash
pastis-afl online
```
