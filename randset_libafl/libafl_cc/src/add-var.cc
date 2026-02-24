#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
    class AddCfgLogSection : public ModulePass {
    public:
        static char ID;
        AddCfgLogSection() : ModulePass(ID) {}

        bool runOnModule(Module &M) override {
            LLVMContext &Context = M.getContext();

            // Define the type for the global variable (array of 16 bytes)
            Type *ArrayType = ArrayType::get(Type::getInt8Ty(Context), 16);

            // Create the global variable with the custom section
            GlobalVariable *GV = new GlobalVariable(
                M, ArrayType, true, GlobalValue::PrivateLinkage,
                ConstantAggregateZero::get(ArrayType), ".cfg_log_section");

            // Set the section attribute
            GV->setSection(".cfg_log_section");

            errs() << "Added .cfg_log_section to the module.\n";
            return true;
        }
    };

    char AddCfgLogSection::ID = 0;
    RegisterPass<AddCfgLogSection X>(
        "add-cfg-log-section", "Add .cfg_log_section to the IR", false, false);
}

// This is the entry point for the pass
extern "C" void LLVMInitializeAddCfgLogSectionPass() {
    PassRegistry &Registry = *PassRegistry::getPassRegistry();
    initializeAddCfgLogSectionPass(Registry);
}
