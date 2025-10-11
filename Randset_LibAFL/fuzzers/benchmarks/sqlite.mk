CC=
CXX=
AR=
CFLAGS=
LDFLAGS=-pthread -ldl -lz
INCLUDES=-I.
DEFS=-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=250000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384
PWD=$(shell pwd)

sqlite:
	@curl https://sqlite.org/src/tarball/sqlite.tar.gz?r=c78cbf2e86850cc6 -o sqlite3.tar.gz
	@tar xzf sqlite3.tar.gz

.PHONY: download
download: sqlite
	@echo "Downloaded sqlite"

.PHONY: check_env 
check_env:
	@echo "CC=${CC}"
	@echo "CXX=${CXX}"
	@echo "AR=${AR}"

sqlite/build/Makefile:
	@mkdir -p sqlite/build
	@cd sqlite/build && CC=${CC} CXX=${CXX} AR=${AR} ../configure --disable-werror

.PHONY: configure 
configure: sqlite/build/Makefile
	@echo "Configured sqlite"

sqlite/build/libsqlite3.a: configure
	@cd sqlite/build && make && make sqlite3.c && \
	${CC} ${CFLAGS} ${DEFS} ${INCLUDES} -c sqlite3.c -o sqlite3.o && \
	${AR} rcs libsqlite3.a sqlite3.o

.PHONY: lib
lib: sqlite/build/libsqlite3.a
	@ls sqlite/build/libsqlite3.a

sqlite/build/harness.o: lib
	@cd sqlite/build && ${CC} ${CFLAGS} ${DEFS} ${INCLUDES} -c ../test/ossfuzz.c -o harness.o

fuzzer_ossfuzz: sqlite/build/harness.o sqlite/build/libsqlite3.a 
	@${CXX} ${LDFLAGS} sqlite/build/harness.o sqlite/build/libsqlite3.a -o fuzzer_ossfuzz

fuzzer_ossfuzz_cfg: fuzzer_ossfuzz
	@./build_cfg.sh fuzzer_ossfuzz

.PHONY: fuzzer 
fuzzer: fuzzer_ossfuzz
	@ls fuzzer_ossfuzz

.PHONY: cfg
cfg: fuzzer_ossfuzz_cfg
	@ls fuzzer_ossfuzz_cfg

all: cfg

.PHONY: clean 
clean:
	-rm -rf sqlite/build fuzzer_ossfuzz*
