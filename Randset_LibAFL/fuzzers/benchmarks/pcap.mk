CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=
CXXFLAGS=
LDFLAGS=
INCLUDES=
DEFS=-I..
PWD=$(shell pwd)

all: cfg

libpcap:
	@git clone git@github.com:the-tcpdump-group/libpcap.git libpcap || true

tcpdump:
	@git clone git@github.com:the-tcpdump-group/tcpdump.git tcpdump || true

.PHONY: download 
download: libpcap tcpdump
	@git -C tcpdump/ checkout 032e4923e5202ea4d5a6d1cead83ed1927135874 

.PHONY: lib 
lib: download
	stat libpcap/build/run/fuzz_both || ( mkdir -p libpcap/build && cd libpcap/build && \
	cmake -DDISABLE_DBUS=1 -DCMAKE_AR=${AR} -DCMAKE_CXX_COMPILER=${CXX} \
		-DCMAKE_CC_COMPILER=${CC} .. && \
	make )

.PHONY: obj 
obj: lib
	stat libpcap/build/fuzzer.o || ( \
		cd libpcap/build/ && ${CC} ${CFLAGS} ${INCLUDES} ${DEFS} \
		-c ../testprogs/fuzz/fuzz_both.c -o fuzzer.o )
	
FUZZER=fuzzer_pcap

${FUZZER}: lib obj 
	${CXX} ${LDFLAGS} libpcap/build/fuzzer.o libpcap/build/libpcap.a -o ${FUZZER}

.PHONY: cfg 
cfg: ${FUZZER}
	@./build_cfg.sh ${FUZZER}
