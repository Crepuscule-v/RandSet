#!/usr/bin/bash

CLANG=$HOME/go/bin/gclang \
CLANGPP=$HOME/go/bin/gclang++ \
LLVM_AR=/usr/bin/llvm-ar-15 \
GET_BC=$HOME/go/bin/get-bc \
LLVM_CC_NAME=/usr/bin/clang-15 \
LLVM_CXX_NAME=/usr/bin/clang++-15 \
LLVM_DIS=/usr/bin/llvm-dis-15 \
LLVM_AR_NAME=/usr/bin/llvm-ar-15 \
LLVM_LINK_NAME=/usr/bin/llvm-link-15 \
OPT=/usr/bin/opt-15 \
	cargo make cfg 
