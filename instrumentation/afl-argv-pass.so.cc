#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "config.h"

#include "llvm/Config/llvm-config.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#if LLVM_VERSION_MAJOR >= 14                /* how about stable interfaces? */
  #include "llvm/Passes/OptimizationLevel.h"
#endif

#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif


#include <set>
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
class ArgvTransform : public PassInfoMixin<ArgvTransform> {

 public:
  ArgvTransform() {

#else
class ArgvTransform : public ModulePass {

 public:
  static char ID;
  ArgvTransform() : ModulePass(ID) {

#endif
    initInstrumentList();

  }

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool      runOnModule(Module &M) override;

  #if LLVM_VERSION_MAJOR >= 4
  StringRef getPassName() const override {

  #else
  const char *getPassName() const override {

  #endif
    return "argv pass";
  }

#endif
 private:
  void insert_argv(Function * main_func);
  void insert_func_probe();
  void replace_open_funcs();

  Module *Mod;
  LLVMContext *Context;
  const DataLayout *DL;
  IRBuilder<> *IRB;

  Type * VoidTy;
  Type * Int32Ty;
  Type * Int8Ty;
  Type * Int8PtrTy;
  Type * Int8PtrPtrTy;
  Type * Int32PtrTy;
  Type * FilePtrTy;
};

}  // namespace

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "argvtransform", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(ArgvTransform());

                });

  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {

              if (Name == "argvtransform") {

                MPM.addPass(ArgvTransform());
                return true;

              } else { return false;}
            });
  #endif
          }};
}

#else
char ArgvTransform::ID = 0;
#endif

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
PreservedAnalyses ArgvTransform::run(Module                &M,
                                      ModuleAnalysisManager &MAM) {

#else
bool ArgvTransform::runOnModule(Module &M) {
#endif

  if ((isatty(2) && getenv("AFL_QUIET") == NULL) || getenv("AFL_DEBUG") != NULL)
    printf("Running argv-pass\n");
  else
    be_quiet = 1;

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  auto PA = PreservedAnalyses::all();
#endif
  Function * main_func = NULL;
  for (auto &F: M) {
    if (F.getName() == "main") {
      main_func = &F;
      break;
    }
  }

  if (main_func == NULL) {
    errs() << "No main function found, skipping argv-pass\n";
    return PA;
  }

  Mod = &M;
  Context = &M.getContext();
  DL = &M.getDataLayout();
  IRB = new IRBuilder<>(*Context);

  VoidTy = Type::getVoidTy(*Context);
  Int32Ty = Type::getInt32Ty(*Context);
  Int8Ty = Type::getInt8Ty(*Context);
  Int8PtrTy = PointerType::get(Int8Ty, 0);
  Int8PtrPtrTy = PointerType::get(Int8PtrTy, 0);
  Int32PtrTy = PointerType::get(Int32Ty, 0);

  FilePtrTy = NULL;
  for (auto &type : M.getIdentifiedStructTypes()) {
    if (type->getName().startswith("struct._IO_FILE")) {
      FilePtrTy = PointerType::get(type, 0);
      break;
    }
  }

  if (FilePtrTy == nullptr) {
    errs() << "Can't find IO_FILE type! Abort.\n";
    return PA;
  }

  insert_argv(main_func);

  replace_open_funcs();

  insert_func_probe();

  if (getenv("DUMP_IR") != NULL) {
    errs() << "Dumping IR after argv-pass\n";
    M.dump();
  }

  delete IRB;

  errs() << "argv-pass done, verifying...\n";
  std::string out;
  llvm::raw_string_ostream os(out);
  bool has_error = verifyModule(M, &os);

  if (has_error) {
    errs() << "Error in module after argv-pass:\n";
    errs() << os.str();
  }

  errs() << "Verify done\n";

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  return PA;
#else
  return true;
#endif
}

#if LLVM_VERSION_MAJOR < 11                         /* use old pass manager */
static void registerArgvTransPass(const PassManagerBuilder &,
                                           legacy::PassManagerBase &PM) {
  auto p = new ArgvTransform();
  PM.add(p);
}

static RegisterStandardPasses RegisterArgvTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerArgvTransPass);

static RegisterStandardPasses RegisterArgvTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerArgvTransPass);

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterArgvTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerArgvTransPass);
  #endif
#endif


void ArgvTransform::insert_argv(Function * main_func) {
  IRB->SetInsertPoint(main_func->getEntryBlock().getFirstNonPHIOrDbgOrLifetime());

  if (main_func->arg_size() != 2) {
    return;
  }

  Value *argc = main_func->getArg(0);
  Value *argv = main_func->getArg(1);
  AllocaInst *argc_ptr = IRB->CreateAlloca(Int32Ty);
  AllocaInst *argv_ptr = IRB->CreateAlloca(Int8PtrPtrTy);

  LoadInst * new_argc = IRB->CreateLoad(Int32Ty, argc_ptr);
  Value * new_argv = IRB->CreateLoad(Int8PtrPtrTy, argv_ptr);

  argc->replaceAllUsesWith(new_argc);
  argv->replaceAllUsesWith(new_argv);

  FunctionCallee argv_change_func = Mod->getOrInsertFunction(
      "__afl_change_argv", Int8PtrPtrTy, Int32PtrTy, Int8PtrPtrTy);
  
  IRB->SetInsertPoint(new_argc);

  Value * new_argv_ptr = IRB->CreateCall(argv_change_func, {argc_ptr, argv});
  IRB->CreateStore(new_argv_ptr, argv_ptr);
}

void ArgvTransform::replace_open_funcs() {

  Value * fopen_wrapperHook = Mod->getOrInsertFunction("__afl_fopen_wrapper", FilePtrTy, Int8PtrTy, Int8PtrTy).getCallee();
  Value * freopen_wrapperHook = Mod->getOrInsertFunction("__afl_freopen_wrapper", FilePtrTy, Int8PtrTy, Int8PtrTy, FilePtrTy).getCallee();
  FunctionCallee open_wrapperHookFC = Mod->getOrInsertFunction("__afl_open_wrapper", Int32Ty, Int8PtrTy, Int32Ty);
  Value * open_wrapperHook = open_wrapperHookFC.getCallee();
  FunctionType * open_ft = FunctionType::get(Int32Ty, {Int8PtrTy, Int32Ty}, true);
  FunctionCallee open_wrapperHookFC2 = Mod->getOrInsertFunction("__afl_open_wrapper2", open_ft);
  Value * open_wrapperHook2 = open_wrapperHookFC2.getCallee();
  Value * creat_wrapperHook = Mod->getOrInsertFunction("__afl_creat_wrapper", Int32Ty, Int8PtrTy, Int32Ty).getCallee();
  Value * mkstemp_wrapperHook = Mod->getOrInsertFunction("__afl_mkstemp_wrapper", Int32Ty, Int8PtrTy).getCallee();
  Value * mkstemps_wrapperHook = Mod->getOrInsertFunction("__afl_mkstemps_wrapper", Int32Ty, Int8PtrTy, Int32Ty).getCallee();
  //Value * mkostemp_wrapperHook = Mod->getOrInsertFunction("__afl_mkostemp_wrapper", Int32Ty, Int8PtrTy, Int32Ty).getCallee();
  //Value * mkostemps_wrapperHook = Mod->getOrInsertFunction("__afl_mkostemps_wrapper", Int32Ty, Int8PtrTy, Int32Ty, Int32Ty).getCallee();
  //Value * mkdtemp_wrapperHook = Mod->getOrInsertFunction("__afl_mkdtemp_wrapper", Int8PtrTy, Int8PtrTy).getCallee();

  for (auto &F : *Mod) {
    StringRef func_name = F.getName();
    if (func_name == "open") {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() >= 2 &&
          ft->getReturnType()->isIntegerTy(32) &&
          ft->getParamType(0)->isPointerTy() &&
          ft->getParamType(1)->isIntegerTy(32)) {
        errs() << "replacing open\n";

        if (ft->isVarArg()) {
          F.replaceAllUsesWith(open_wrapperHook2);
        } else {
          F.replaceAllUsesWith(open_wrapperHook);

          for (auto iter = open_wrapperHook->user_begin(); iter != open_wrapperHook->user_end(); iter++) {
            Value * user = *iter;

            user->dump();

            if (!isa<CallInst>(*iter)) { continue;}

            CallInst * call = cast<CallInst>(*iter);

            if (call->getNumArgOperands() != 3) { continue; }

            IRB->SetInsertPoint(call);
            Value * arg0 = call->getArgOperand(0);
            Value * arg1 = call->getArgOperand(1);

            Value * new_call = IRB->CreateCall(open_wrapperHookFC, {arg0, arg1});
            call->replaceAllUsesWith(new_call);
            call->eraseFromParent();
          }
        }
        continue;
      }
    } else if (func_name == "fopen") {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 2 &&
          ft->getReturnType()->isPointerTy() &&
          ft->getParamType(0)->isPointerTy() &&
          ft->getParamType(1)->isPointerTy()) {
        errs() << "replacing fopen\n";
        F.replaceAllUsesWith(fopen_wrapperHook);
        continue;
      }
    } else if (func_name == "freopen") {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 3 &&
        ft->getReturnType()->isPointerTy() &&
        ft->getParamType(0)->isPointerTy() &&
        ft->getParamType(1)->isPointerTy() &&
        ft->getParamType(2)->isPointerTy()) {
        F.replaceAllUsesWith(freopen_wrapperHook);
        continue;
      }
    } else if (func_name == "creat") {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 2 &&
      ft->getReturnType()->isIntegerTy(32) &&
      ft->getParamType(0)->isPointerTy() &&
      ft->getParamType(1)->isIntegerTy(32)) {
        F.replaceAllUsesWith(creat_wrapperHook);
        continue;
      }
    } else if (func_name == "mkstemp") {
      // replacing mkstemp(char * template)
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 1 &&
      ft->getReturnType()->isIntegerTy(32) &&
      ft->getParamType(0)->isPointerTy()) {
        errs() << "replacing mkstemp\n"; // CREATE FILE LOG
        F.replaceAllUsesWith(mkstemp_wrapperHook);
        continue;
      }
    } else if (func_name == "mkstemps") {
      // replacing mkstemps(char * template, int flag)
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 2 &&
      ft->getReturnType()->isIntegerTy(32) &&
      ft->getParamType(0)->isPointerTy() &&
      ft->getParamType(1)->isIntegerTy(32)) {
        errs() << "replacing mkstemps\n";  // CREATE FILE LOG
        F.replaceAllUsesWith(mkstemps_wrapperHook);
        continue;
      }
    } /*else if (func_name == "mkostemp") {
      // replacing mkostemp(char * template, int flag)
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 2 &&
      ft->getReturnType()->isIntegerTy(32) &&
      ft->getParamType(0)->isPointerTy() &&
      ft->getParamType(1)->isIntegerTy(32)) {
        // errs() << "replacing mkostemp\n");  // CREATE FILE LOG
        F.replaceAllUsesWith(mkostemp_wrapperHook);
        continue;
      }
    } else if (func_name == "mkostemps") {
      // replacing mkstemps(char * template, int flag)
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 2 &&
      ft->getReturnType()->isIntegerTy(32) &&
      ft->getParamType(0)->isPointerTy() &&
      ft->getParamType(1)->isIntegerTy(32) &&
      ft->getParamType(2)->isIntegerTy(32)) {
        // errs() << "replacing mkostemps\n"); // CREATE FILE LOG
        F.replaceAllUsesWith(mkostemps_wrapperHook);
        continue;
      }
    } else if (func_name == "mkdtemp") {
      FunctionType * ft = F.getFunctionType();
      if (ft->getNumParams() == 1 &&
        ft->getReturnType()->isPointerTy() &&
        ft->getParamType(0)->isPointerTy()
      ) {
        errs() << "replacing mkdtemp\n";
        F.replaceAllUsesWith(mkdtemp_wrapperHook);
      }
    }
    */
  }
}

void ArgvTransform::insert_func_probe() {

  Constant *func_map_ptr = Mod->getOrInsertGlobal("__afl_func_map_ptr", Int8PtrTy);

  int func_id = 0;

  for (auto &F : Mod->functions()) {

    if (!isInInstrumentList(&F, Mod->getSourceFileName()))  { continue; }
    if (F.getName() == "main") { continue; }

    BasicBlock &entry = F.getEntryBlock();

    IRB->SetInsertPoint(entry.getFirstNonPHIOrDbgOrLifetime());

    Value * func_map_ptr_val = IRB->CreateLoad(Int8PtrTy, func_map_ptr);

    Value * map_idx_ptr = IRB->CreateInBoundsGEP(Int8Ty, func_map_ptr_val, ConstantInt::get(Int32Ty, func_id));
    IRB->CreateStore(ConstantInt::get(Int8Ty, 1), map_idx_ptr);

    func_id++;

    if (func_id >= FUNC_MAP_SIZE) {
      func_id = 0;
    }
  }
}