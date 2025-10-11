CC=
CXX=
AR=
LIB_FUZZER=
CFLAGS=-fno-sanitize=vptr -DHB_NO_VISIBILITY
CXXFLAGS=-fno-sanitize=vptr -DHB_NO_VISIBILITY
LDFLAGS=
INCLUDES=-I../include
DEFS=
PWD=$(shell pwd)

all: cfg 

json:
	@git clone https://github.com/open-source-parsers/jsoncpp json
	@mkdir -p json/build

.PHONY: configure
configure: json
	@cd json && mkdir -p build && cd build && \
	cmake -DCMAKE_CXX_COMPILER=${CXX} -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
	  -DCMAKE_AR=${AR} \
      -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF -DJSONCPP_WITH_TESTS=OFF \
      -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles" ..

.PHONY: lib
lib: configure
	@cd json/build && make 

${PWD}/fuzzer_json: lib
	@cd json/build && ${CXX} ${CXXFLAGS} ${INCLUDES} ${DEFS} \
	../src/test_lib_json/fuzz.cpp lib/libjsoncpp.a \
	-o ${PWD}/fuzzer_json

.PHONY: cfg 
cfg: ${PWD}/fuzzer_json 
	@./build_cfg.sh fuzzer_json.coverage_asan

.PHONY: clean
clean: 
	rm -rf json/build/* fuzzer_json* 
