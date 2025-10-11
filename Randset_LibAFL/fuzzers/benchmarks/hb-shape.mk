CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=-fno-sanitize=vptr -DHB_NO_VISIBILITY
CXXFLAGS=-fno-sanitize=vptr -DHB_NO_VISIBILITY
LDFLAGS=
INCLUDES=
DEFS=
PWD=$(shell pwd)
BUILD=build

all: cfg 

harfbuzz: 
	@git clone https://github.com/harfbuzz/harfbuzz.git

.PHONY: configure 
configure: harfbuzz
	@cd harfbuzz && CFLAGS="${CFLAGS}" CXXFLAGS="${CXXFLAGS}" meson --default-library=static --wrap-mode=nodownload \
      -Dexperimental_api=true \
      -Dfuzzer_ldflags= \
      ${BUILD}

FUZZER=harfbuzz/build/test/fuzzing/hb-shape-fuzzer
${FUZZER}: configure
	@echo "" > harfbuzz/test/fuzzing/main.cc
	@cd harfbuzz && ninja -v -C ${BUILD} test/fuzzing/hb-shape-fuzzer

.PHONY: fuzzer 
fuzzer: $(FUZZER)
	@ldd $(FUZZER) > /dev/null

.PHONY: cfg 
cfg: ${FUZZER}
	@cp ${FUZZER} ./fuzzer_hbshape
	@./build_cfg.sh ./fuzzer_hbshape

.PHONY: clean 
clean:
	@rm -rf harfbuzz/build fuzzer_hbshape* 
