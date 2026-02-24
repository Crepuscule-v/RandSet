CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=
LDFLAGS=
INCLUDES=
DEFS=
PWD=$(shell pwd)

bloaty:
	@git clone --depth 1 https://github.com/google/bloaty.git
	@mkdir -p bloaty/build

.PHONY: download
download: bloaty
	@echo "Downloaded bloaty"

bloaty/build/build.ninja: bloaty
	@mkdir -p bloaty/build
	@cd bloaty/build && LIB_FUZZING_ENGINE=${LIB_FUZZER} cmake -G Ninja -DCMAKE_C_COMPILER=${CC} -DCMAKE_CXX_COMPILER=${CXX} \
	-DCMAKE_AR=${AR} -DBUILD_TESTING=true ..

.PHONY: configure
configure: bloaty/build/build.ninja
	@ls bloaty/build/build.ninja > /dev/null

bloaty/build/liblibbloaty.a: configure
	@ninja -C bloaty/build 

.PHONY: lib 
lib: bloaty/build/liblibbloaty.a
	@ls bloaty/build/liblibbloaty.a > /dev/null

.PHONY: fuzzer 
fuzzer: lib
	@ldd ./bloaty/build/fuzz_target > /dev/null

.PHONY: cfg 
cfg: fuzzer
	@./build_cfg.sh ./bloaty/build/fuzz_target

.PHONY: clean
clean:
	@ninja -C bloaty/build clean
	@rm -f *.o *.cfg fuzzer_bloaty*

all: cfg
