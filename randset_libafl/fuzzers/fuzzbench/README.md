# Fuzzbench

This folder contains fuzzers for benchmarking.

# Usage

Suppose you are going to make a fuzzer for `BENCHMARK`:

```sh
cd $BENCHMARK
cargo build --release --features [default,queue,setcover]
cargo make fuzzer
cargo make cfg
```

The `setcover` method requires a control flow graph, which is 
generated via `cargo make cfg`. Run the fuzzer by:

```sh
AFL_CFG_PATH=/PATH/TO/"$FUZZER_NAME"_sancov_cfg $FUZZER_NAME --cores 0 --input input
```
