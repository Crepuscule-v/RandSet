#!/usr/bin/bash

python3 -m pip install meson==0.56.0 ninja

export CC=$LIBAFL_CC
export CXX=$LIBAFL_CXX
export AR=$LIBAFL_AR

export CFLAGS="$CFLAGS -fno-sanitize=vptr -DHB_NO_VISIBILITY -DHB_NO_PRAGMA_GCC_DIAGNOSTIC -Wno-cast-function-type-strict -Wno-incompatible-function-pointer-types-strict"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr -DHB_NO_VISIBILITY -DHB_NO_PRAGMA_GCC_DIAGNOSTIC -Wno-cast-function-type-strict -Wno-incompatible-function-pointer-types-strict"

cd harfbuzz
build=$PWD/build

rm -rf $build && mkdir -p $build
meson --default-library=static --wrap-mode=nodownload \
      -Dexperimental_api=true \
      -Dfuzzer_ldflags="$(echo $LIB_FUZZING_ENGINE)" \
      $build \
  || (cat build/meson-logs/meson-log.txt && false)

# Build the fuzzers.
ninja -v -C $build test/fuzzing/hb-shape-fuzzer
