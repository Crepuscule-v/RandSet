INSTALL_PREFIX=${PWD}/proj-install
FUZZER=fuzzer_proj
CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=
CXXFLAGS=-std=c++11 -fvisibility=hidden
LDFLAGS=-lpthread -Wl,-Bstatic -L${INSTALL_PREFIX}/lib -lproj -lsqlite3 -ltiff -lcurl -lssl -lcrypto -lz -Wl,-Bdynamic
INCLUDES=-Iproj/src -Iproj/include
DEFS=
PWD=$(shell pwd)
CURL=$(shell which curl)

CONFIG_ENV = CC=${CC} CXX=${CXX} AR=${AR}
CMAKE_DEFS = -DCMAKE_AR=${AR} -DCMAKE_CXX_COMPILER=${CXX} -DCMAKE_CC_COMPILER=${CC}

all: ${FUZZER}

proj:
	@git clone https://github.com/OSGeo/PROJ proj || ls proj

proj/curl:
	git clone https://github.com/curl/curl proj/curl || ls proj/curl

proj/libtiff:
	git clone https://gitlab.com/libtiff/libtiff proj/libtiff || ls proj/libtiff

proj/sqlite:
	@ls proj/sqlite || ( \
	${CURL} https://sqlite.org/src/tarball/sqlite.tar.gz?r=c78cbf2e86850cc6 -o proj/sqlite3.tar.gz && \
	cd proj && tar xzf sqlite3.tar.gz )

.PHONY: download 
download: proj proj/curl proj/libtiff
	@mkdir -p proj-install
	@ls ${INSTALL_PREFIX}/ > /dev/null
	@ls proj proj/curl proj/libtiff > /dev/null

.PHONY: libsqlite 
libsqlite: proj/sqlite
	@ls proj-install/lib/libsqlite3.a || ( \
	cd proj/sqlite && mkdir -p build && cd build \
	&& ${CONFIG_ENV} ../configure --prefix=${INSTALL_PREFIX} --disable-shared && make && make install \
	)

.PHONY: libcurl 
libcurl: proj/curl
	@ls proj-install/lib/libcurl.a || \
	( cd proj/curl && ${CONFIG_ENV} autoreconf -i && \
	${CONFIG_ENV} ./configure --disable-shared --with-openssl --prefix=${INSTALL_PREFIX} && \
	make clean -s && make && make install )

.PHONY: libtiff 
libtiff: proj/libtiff
	@ls proj-install/lib/libtiff.a || ( \
		cd proj/libtiff && ${CONFIG_ENV} ./autogen.sh && \
		${CONFIG_ENV} ./configure --disable-shared --with-openssl --prefix=${INSTALL_PREFIX} && \
		make install )

.PHONY: libproj
libproj: libtiff libcurl libsqlite
	@ls proj-install/lib/libproj.a || ( \
	cd proj/ && mkdir -p build && cd build && \
	cmake .. -DBUILD_SHARED_LIBS:BOOL=OFF \
        -DCURL_INCLUDE_DIR:PATH="${INSTALL_PREFIX}/include" \
        -DCURL_LIBRARY_RELEASE:FILEPATH="${INSTALL_PREFIX}/lib/libcurl.a" \
		-DSQLITE_INCLUDE_DIR:PATH="${INSTALL_PREFIX}/include" \
        -DSQLITE_LIBRARY_RELEASE:FILEPATH="${INSTALL_PREFIX}/lib/libsqlite3.a" \
        -DTIFF_INCLUDE_DIR:PATH="${INSTALL_PREFIX}/include" \
        -DTIFF_LIBRARY_RELEASE:FILEPATH="${INSTALL_PREFIX}/lib/libtiff.a" \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
        -DBUILD_APPS:BOOL=OFF \
        -DBUILD_TESTING:BOOL=OFF ${CMAKE_DEFS} && \
	make && make install )

proj.o: proj/test/fuzzers/proj_crs_to_crs_fuzzer.cpp
	${CXX} ${CXXFLAGS} ${INCLUDES} ${DEFS} -c proj/test/fuzzers/proj_crs_to_crs_fuzzer.cpp \
	-o proj.o

${FUZZER}: libsqlite proj.o libproj libtiff libcurl
	${CXX} -o ${FUZZER}  proj.o ${LDFLAGS}

.PHONY: clean 
clean:
	-make clean -C proj/sqlite/build
	-make clean -C proj/curl
	-rm -r proj-install/* proj/build
	-rm -f fuzzer_proj* *.o .*.bc *.a
