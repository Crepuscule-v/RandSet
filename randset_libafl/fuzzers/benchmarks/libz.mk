CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=
CXXFLAGS=-std=c++11
LDFLAGS=
INCLUDES=-Izlib-fuzz/
DEFS=
PWD=$(shell pwd)

FUZZER = fuzzer_libz
all: ${FUZZER}_cfg

zlib-fuzz:
	@git clone --depth 1 -b develop https://github.com/madler/zlib.git zlib-fuzz

zlib-fuzz/libz.a: zlib-fuzz
	@cd zlib-fuzz && CC=${CC} CXX=${CXX} AR=${AR} ./configure && make 

.PHONY: lib
lib: zlib-fuzz/libz.a
	@size zlib-fuzz/libz.a > /dev/null

libz.o: zlib-fuzz fuzzer/libz.cc 
	${CXX} ${CXXFLAGS} ${INCLUDES} ${DEFS} -c fuzzer/libz.cc -o libz.o

${FUZZER}: libz.o lib
	${CXX} ${LDFLAGS} libz.o zlib-fuzz/libz.a -o ${FUZZER}

${FUZZER}_cfg: ${FUZZER}
	@./build_cfg.sh ${FUZZER}

.PHONY: clean 
clean:
	-rm fuzzer_libz*
	-make -C zlib-fuzz clean
