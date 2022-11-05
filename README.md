For each target, this repository expects a directory with the following structure

- `bins` containing the binaries for AFL and tritondse
- `cmplog` containing the binary instrumented for cmplog
- `seeds` containing the initial fuzzing seeds
- `results` empty. This is where the pastis corpus will be placed

There is an example for `libpng`.

Then set the globals in `bench.py` and configure the desired options with `run_instance`. 
`python3 bench.py` will launch the experiment.


