# Pastis Benchmark

The tool works around the patis-broker workspace. It works with and will add new files
into it for its processing (input replay, graph drawing etc).

## Running a benchmark

A benchmark can be launched with:

```bash
pastis-benchmark run -w my-xp-workspace -b targets/freetype/bins/ -s targets/freetype/seeds --aflpp --honggfuzz --debug
```

This will launch the broker with ``my-xp-workspace`` as workspace directory.

The workspace will have the followintg structure:

```
my-xp-workspace/
    corpus/
    crashes/
    hangs/
    logs/
    client-stats.json
    telemetry.csv
    client_ws/  <-- added by pastis-benchmark
        aflpp/
        hfuzz/ 
    triton_confs/  <-- you can write your triton configs here
```

If you want to launch triton with various configurations, you can create configuration
files in the ``triton_confs/`` directory. They will be automatically read and provided
to the broker (and ultimately to triton instances).

## Replaying corpus

TODO

## Plotting results

TODO