CC=
CXX=
AR=
CFLAGS=
LDFLAGS=-Wl,-Bstatic -lz -llzma -Wl,-Bdynamic
INCLUDES=-Ixml2/include/
DEFS=
PWD=$(shell pwd)

xml2:
	@git clone https://gitlab.gnome.org/GNOME/libxml2.git ./xml2 --depth 1

.PHONY: download
download: xml2
	@echo "Downloaded xml2"

xml2/Makefile:
	@cd xml2 && CC=${CC} CXX=${CXX} AR=${AR} ./autogen.sh && \
	CC=${CC} CXX=${CXX} AR=${AR} ./configure --enable-static=yes --enable-shared=no

.PHONY: configure
configure: xml2/Makefile
	@ls xml2/Makefile > /dev/null

xml2/.libs/libxml2.a: configure
	@cd xml2 && make CC=${CC} CXX=${CXX} AR=${AR}

.PHONY: lib
lib: xml2/.libs/libxml2.a
	@ls xml2/.libs/libxml2.a

xml2.o: fuzzer/xml2.cc xml2/.libs/libxml2.a
	@${CXX} ${CFLAGS} ${DEFS} ${INCLUDES} -c fuzzer/xml2.cc -o xml2.o

fuzzer_xml2: xml2.o xml2/.libs/libxml2.a 
	@${CXX} ${LDFLAGS} xml2.o xml2/.libs/libxml2.a -o fuzzer_xml2

.PHONY: fuzzer
fuzzer:
	@ls fuzzer_xml2

fuzzer_xml2_cfg: fuzzer_xml2
	@./build_cfg.sh fuzzer_xml2

.PHONY: cfg
cfg: fuzzer_xml2_cfg
	@ls fuzzer_xml2_cfg

all: cfg

.PHONY: clean
clean:
	@make -C xml2 clean
	@rm -f *.o *.cfg fuzzer_xml2*
