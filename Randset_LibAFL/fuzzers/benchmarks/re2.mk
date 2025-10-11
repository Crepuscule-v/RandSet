CC=
CXX=
AR=
CFLAGS=-std=c++17
LDFLAGS=-lpthread
INCLUDES=-I./re2 -I./re2/abseil-cpp/
DEFS=
PWD=$(shell pwd)

all: cfg

re2:
	@git clone https://github.com/google/re2.git

re2/abseil-cpp: re2
	@cd re2 && git clone https://github.com/abseil/abseil-cpp || true

re2/googletest: re2 
	@cd re2 && git clone https://github.com/google/googletest || true

re2/benchmark: re2
	@cd re2 && git clone https://github.com/google/benchmark || true

.PHONY: dep
dep: re2 re2/googletest re2/abseil-cpp re2/benchmark 
	@ls re2 > /dev/null
	@ls re2/googletest > /dev/null
	@ls re2/abseil-cpp > /dev/null
	@ls re2/benchmark > /dev/null

re2/build/Makefile: re2 dep
	@mkdir -p re2/build
	@cd re2/build && cmake -DCMAKE_CC_COMPILER=${CC} \
		-DCMAKE_CXX_COMPILER=${CXX} \
		-DCMAKE_AR=${AR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..

.PHONY: configure
configure: re2/build/Makefile
	@ls re2/build/Makefile > /dev/null

re2/build/libre2.a: re2/build/Makefile 
	@cd re2/build && make 

.PHONY: lib 
lib: re2/build/libre2.a 
	@size re2/build/libre2.a > /dev/null

re2.o: fuzzer/re2.cc
	${CXX} ${CFLAGS} ${INCLUDES} ${DEFS} -c fuzzer/re2.cc -o re2.o

fuzzer_re2:	re2/build/libre2.a re2.o
	${CXX} ${LDFLAGS} re2.o ./re2/build/libre2.a $(shell find -wholename ./re2/build/abseil-cpp/*.o) \
	-o fuzzer_re2 

.PHONY: cfg 
cfg: fuzzer_re2 
	@./build_cfg.sh fuzzer_re2

.PHONY: clean
clean:
	-rm -rf ./re2/build re2.o fuzzer_re2*
