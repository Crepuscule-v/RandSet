# Test that LibAFL works

Creating unit tests for fuzzer is difficult.
Instead we provide a simple C library to check that
the fuzzer works.

## Step 1
Run:
```sh
cargo make fuzzer && cargo make cfg
```

You should see a file named [fuzzer_libstr_sancov_cfg](./fuzzer_libstr_sancov_cfg).
If instrumentation is correct, the first 6 lines of file
`fuzzer_libstr_sancov_cfg` should look exactly like this:
```
0 1
0 2
2 4
2 3
3 9
4 6
```

The control flow graph of this lib is shown in [cfg.json](./cfg.json).

## Step 2

Try running the fuzzer:
```sh
AFL_CFG_PATH=$PWD/fuzzer_libstr_sancov_cfg ./fuzzer_libstr.asan --cores 0 --input ./input
```

You should observe that the coverage rises to over 76\% after no more than 10 seconds.
