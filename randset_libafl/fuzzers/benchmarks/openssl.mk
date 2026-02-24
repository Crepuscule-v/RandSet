CC=
CXX=
AR=
CFLAGS=-g -O0 -m64 -Wall -fno-sanitize=alignment -fno-omit-frame-pointer
LDFLAGS=-ldl -lpthread
INCLUDES=-Iopenssl/include -Iopenssl/fuzz
DEFS=-DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
PWD=$(shell pwd)

.PHONY: alias
alias:
	@echo x509

openssl:
	@git clone --depth 1 --branch openssl-3.0.7 https://github.com/openssl/openssl.git

.PHONY: download
download: openssl
	@echo "Downloaded openssl"

openssl/Makefile: openssl
	@cd openssl && CC=${CC} CXX=${CXX} AR=${AR} ./config \
	--debug enable-fuzz-libfuzzer ${DEFS} no-shared enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers -fno-sanitize=alignment

.PHONY: configure 
configure: openssl/Makefile
	@ls openssl/Makefile > /dev/null

openssl/libcrypto.a: configure
	@cd openssl && make LDCMD="${CXX}" CC=${CC} CXX=${CXX} AR=${AR}

openssl/fuzz/x509-test-bin-fuzz_rand.o: configure 
	@cd openssl && make LDCMD="${CXX}" CC=${CC} CXX=${CXX} AR=${AR} fuzz/x509-test-bin-fuzz_rand.o

openssl.o: fuzzer/openssl.cc openssl/libcrypto.a
	@${CXX} ${CFLAGS} ${DEFS} ${INCLUDES} -c fuzzer/openssl.cc -o openssl.o

fuzzer_openssl: openssl.o openssl/libcrypto.a openssl/fuzz/x509-test-bin-fuzz_rand.o
	@${CXX} ${LDFLAGS} openssl.o openssl/libcrypto.a \
	openssl/fuzz/x509-test-bin-fuzz_rand.o \
	-o fuzzer_openssl

.PHONY: fuzzer 
fuzzer: fuzzer_openssl
	@ls fuzzer_openssl

fuzzer_openssl.coverage_asan_cfg: fuzzer_openssl
	@./build_cfg.sh fuzzer_openssl.coverage_asan

.PHONY: cfg
cfg: fuzzer_openssl.coverage_asan_cfg
	@ls fuzzer_openssl.coverage_asan_cfg

all: cfg

.PHONY: clean
clean:
	@make -C openssl clean
	@rm -f *.o *.cfg fuzzer_openssl*
