CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=
LDFLAGS=
INCLUDES=
DEFS=
PWD=$(shell pwd)

LIBARCHIVE_VERSION=$(shell pkg-config --modversion libarchive)

all: fuzzer 

freetype2:
	@git clone git://git.sv.nongnu.org/freetype/freetype2.git

.PHONY: download
download: freetype2
	@echo "Downloaded freetype2"

.PHONY: configure 
configure: freetype2
	@cd freetype2 && ./autogen.sh && \
	./configure --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib

freetype2/objs/.libs/libfreetype.a: configure
	@make -C freetype2

fuzzer_freetype2: freetype2/objs/.libs/libfreetype.a
	@cd freetype2 && ${CXX} -I include -I . src/tools/ftfuzzer/ftfuzzer.cc \
	objs/.libs/libfreetype.a -L /usr/local/lib -larchive 

.PHONY: lib
lib: freetype2/objs/.libs/libfreetype.a
	@ls freetype2/objs/.libs/libfreetype.a > /dev/null

.PHONY: fuzzer
fuzzer: fuzzer_freetype2
	@ldd ./freetype2/fuzzer_freetype2 > /dev/null
