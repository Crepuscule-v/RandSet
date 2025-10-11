CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=
LDFLAGS=
INCLUDES=
DEFS=
PWD=$(shell pwd)

all: cfg 

.PHONY: build 
build:
	@cd curl_fuzzer && \
		CC=${CC} CXX=${CXX} CFLAGS=${CFLAGS} CXXFLAGS=${CXXFLAGS} \
		SANITIZER= LIB_FUZZING_ENGINE= SRC_DIR=${PWD} AR=${AR} \
		ARCHITECTURE= ./ossfuzz.sh

.PHONY: cfg 
cfg: build
	@./build_cfg.sh ./curl_fuzzer/curl_fuzzer
