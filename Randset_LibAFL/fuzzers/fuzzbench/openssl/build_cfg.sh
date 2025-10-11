#!/usr/bin/bash

$GET_BC $1

bc="$1.bc"
$LLVM_DIS $bc -o "$1".ll

cfg_pass=$( find -name dump-cfg-pass.so )

CFG_OUTPUT_PATH=$PWD $LLVM_CC_NAME -c -Xclang -load \
  -Xclang $cfg_pass \
  -Xclang -fpass-plugin=$cfg_pass \
  "$1".ll

# parse the ll for the order of each guard.
cat "$1".ll | \
  grep "compiler" | \
  sed  -E "s/.*\[(.*)\].*/\1/" | \
  sed "s/ptr //g" > "$1".csv

# the pass writes each call to pc guard to "$1.ll.pc"
cat "$1".ll.pc | \
  sed -E "s/.*@__sancov_gen_(.*) to i64\), i64 ([0-9]+).*/@__sancov_gen_\1, \2/g" | \
  sed -E "s/.*@__sancov_gen_(.*)\).*/@__sancov_gen_\1, 0/g" >> "$1".csv

python3 ../gen_graph.py $1
