/*
   LibAFL - DumpCfg LLVM pass
   --------------------------------------------------

   Written by Dongjia Zhang <toka@aflplus.plus>

   Copyright 2022-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
  #include <unistd.h>
  #include <sys/time.h>
#else
  #include <io.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include <list>
#include <string>
#include <fstream>
#include <set>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"

#if USE_NEW_PM
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"

#include <iostream>

#include <nlohmann/json.hpp>

#define FATAL(x...)               \
  do {                            \
    fprintf(stderr, "FATAL: " x); \
    exit(1);                      \
                                  \
  } while (0)

using namespace llvm;

namespace {

#if USE_NEW_PM
class DumpCfgPass : public PassInfoMixin<DumpCfgPass> {
 public:
  DumpCfgPass() {
#else
class DumpCfgPass : public ModulePass {
 public:
  static char ID;

  DumpCfgPass() : ModulePass(ID) {
#endif
  }

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  DenseMap<BasicBlock *, uint32_t>               bb_to_cur_loc;
  DenseMap<StringRef, BasicBlock *>              entry_bb;
  DenseMap<BasicBlock *, std::vector<StringRef>> calls_in_bb;
  std::vector<std::string> calls_to_pc_guard;

 private:
  const std::string sancov_pc_guard_name = "__sanitizer_cov_trace_pc_guard";
  bool isLLVMIntrinsicFn(StringRef &n) {
    // Not interested in these LLVM's functions
#if LLVM_VERSION_MAJOR >= 18
    if (n.starts_with("llvm.")) {
#else
    if (n.startswith("llvm.")) {
#endif
      return true;
    } else {
      return false;
    }
  }
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DumpCfgPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(DumpCfgPass());
                });
          }};
}
#else
char DumpCfgPass::ID = 0;
#endif

#if USE_NEW_PM
PreservedAnalyses DumpCfgPass::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool DumpCfgPass::runOnModule(Module &M) {

#endif
  LLVMContext &Ctx = M.getContext();
  auto         moduleName = M.getName();

  for (auto &F : M) {
    unsigned bb_cnt = 0;
    entry_bb[F.getName()] = &F.getEntryBlock();
    for (auto &BB : F) {
      bb_to_cur_loc[&BB] = bb_cnt;
      bb_cnt++;
      for (auto &IN : BB) {
        CallBase *callBase = nullptr;
        if ((callBase = dyn_cast<CallBase>(&IN))) {
          auto F = callBase->getCalledFunction();
          if (F) {
            StringRef fname = F->getName();
            if (isLLVMIntrinsicFn(fname)) { continue; }

            if (fname == "__sanitizer_cov_trace_pc_guard") {
              // add additional info of this func call,
              // eg. args.
              std::string arg0;
              raw_string_ostream OS(arg0);
              IN.print(OS);

              std::string func_with_arg = arg0;
              // std::cerr << "\033[01;32m[*]\033[0;m" << func_with_arg << std::endl;
              // fname = func_with_arg;
              calls_to_pc_guard.push_back(func_with_arg);
            }

            calls_in_bb[&BB].push_back(fname);
          }
        }
      }
    }
  }

  nlohmann::json cfg;

  // Dump CFG for this module
  size_t num_edges = 0;
  for (auto record = bb_to_cur_loc.begin(); record != bb_to_cur_loc.end();
       record++) {
    BasicBlock *current_bb = record->getFirst();
    uint32_t    loc = record->getSecond();
    Function   *calling_func = current_bb->getParent();
    std::string func_name = std::string("");

    if (calling_func) {
      func_name = std::string(calling_func->getName());
      // outs() << "Function name: " << calling_func->getName() << "\n";
    }

    std::vector<uint32_t> outgoing;
    for (auto bb_successor = succ_begin(current_bb);
         bb_successor != succ_end(current_bb); bb_successor++) {
      outgoing.push_back(bb_to_cur_loc[*bb_successor]);
    }
    num_edges += outgoing.size();
    cfg["edges"][func_name][loc] = outgoing;
  }

  for (auto record = calls_in_bb.begin(); record != calls_in_bb.end();
       record++) {
    auto        current_bb = record->getFirst();
    auto        loc = bb_to_cur_loc[current_bb];
    Function   *calling_func = current_bb->getParent();
    std::string func_name = std::string("");

    if (calling_func) {
      func_name = std::string(calling_func->getName());
      // outs() << "Function name: " << calling_func->getName() << "\n";
    }

    std::vector<std::string> outgoing_funcs;
    for (auto &item : record->getSecond()) {
      outgoing_funcs.push_back(std::string(item));
    }
    if (!outgoing_funcs.empty()) {
      cfg["calls"][func_name][std::to_string(loc)] = outgoing_funcs;
    }
  }

  for (auto record = entry_bb.begin(); record != entry_bb.end(); record++) {
    cfg["entries"][std::string(record->getFirst())] =
        bb_to_cur_loc[record->getSecond()];
  }

  const char *output_path = "";
  if (output_path) {
    std::string cfg_out_path = output_path + 
                               std::string(moduleName) + ".cfg";
    std::ostringstream oss;
    oss << cfg << std::endl;
    int _fd = open(cfg_out_path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (_fd < 0) {
      // cannot create output file.
      fprintf(stderr, "NOTE: output_path %s, module_name %s\n", cfg_out_path.c_str(),
              moduleName.data());
      // if PERMISSION DENIED,
      // try to create the directory first.
      perror("\033[01;31m[!]\033[0;m " __FILE__);
      exit(1);
    }
    write(_fd, oss.str().c_str(), oss.str().size());
    close(_fd);

    // std::ofstream cfg_out(cfg_out_path.c_str());
    // cfg_out << cfg << std::endl;
    // cfg_out.close();

    int fd = open(cfg_out_path.c_str(), O_RDONLY);
    if (fd < 0) {
      perror("\033[01;31m[!]\033[0;m " __FILE__);
      std::cerr << "\033[01;31m[!]\033[0;m dump-cfg-pass IO error!" << std::endl;
      exit(1);
    }
    close(fd);
    std::cerr << "\033[01;32m[+]\033[0;m dump-cfg-pass instrumented " 
      << num_edges << " edges." << std::endl;
    
    std::string pc_guard_path = std::string(moduleName) + ".pc";
    std::ofstream pc_guard_out(pc_guard_path.c_str());
    for (const auto call : this->calls_to_pc_guard) {
      pc_guard_out << call << std::endl;
    }
    pc_guard_out.close();
  } else {
    FATAL("CFG_OUTPUT_PATH not set!");
  }

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
  return PA;
#else
  return true;
#endif
}

#if USE_NEW_PM

#else
static void registerDumpCfgPass(const PassManagerBuilder &,
                                legacy::PassManagerBase &PM) {
  PM.add(new DumpCfgPass());
}

static RegisterPass<DumpCfgPass> X("dumpcfg", "dumpcfg instrumentation pass",
                                   false, false);

static RegisterStandardPasses RegisterDumpCfgPass(
    PassManagerBuilder::EP_OptimizerLast, registerDumpCfgPass);

static RegisterStandardPasses RegisterDumpCfgPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerDumpCfgPass);
#endif
