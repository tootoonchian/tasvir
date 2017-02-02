#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
struct LogWrite : public FunctionPass {
    static char ID;
    LogWrite() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
        // Get the function to call from our runtime library.
        const DataLayout &layout = F.getParent()->getDataLayout();
        LLVMContext &Ctx = F.getContext();
        auto *VoidTy = Type::getVoidTy(Ctx);
        auto *Int8PtrTy = Type::getInt8PtrTy(Ctx);
        // auto *Int32Ty = Type::getInt32Ty(Ctx);
        auto *Int64Ty = Type::getInt32Ty(Ctx);
        Constant *logFunc = F.getParent()->getOrInsertFunction("logop", VoidTy, Int8PtrTy, Int64Ty, NULL);

        for (auto &B : F) {
            for (auto &I : B) {
                Value *dst;
                Value *len;
                if (isa<StoreInst>(I) || isa<AtomicRMWInst>(I)) {
                    dst = I.getOperand(1);
                    len = ConstantInt::get(Int64Ty, layout.getTypeAllocSize(dst->getType()));
                } else if (isa<AtomicCmpXchgInst>(I)) {
                    dst = I.getOperand(0);
                    len = ConstantInt::get(Int64Ty, layout.getTypeAllocSize(dst->getType()));
                } else if (isa<MemIntrinsic>(I)) {
                    auto *op = dyn_cast<MemIntrinsic>(&I);
                    dst = op->getDest();
                    len = op->getLength();
                } else {
                    continue;
                }
                if (isa<AllocaInst>(dst))
                    continue;

                // Insert *after* `op`.
                IRBuilder<> builder(&I);
                builder.SetInsertPoint(&B, ++builder.GetInsertPoint());
                Value *args[] = {dst, len};
                builder.CreateCall(logFunc, args);
                errs() << I << "\n\t";
                errs().write_escaped(I.getOpcodeName()) << " *dst:" << *dst << " dst:" << dst
                                                        << " type:" << *dst->getType() << " len:" << *len << " "
                                                        << '\n';
            }
        }

        return false;
    }

};  // end of struct LogWrite
}  // end of anonymous namespace

char LogWrite::ID = 0;
static RegisterPass<LogWrite> X("logwrite", "Log Writes Pass", false /* Only looks at CFG */,
                                false /* Analysis Pass */);

static void registerLogWritePass(const PassManagerBuilder &, legacy::PassManagerBase &PM) { PM.add(new LogWrite()); }
static RegisterStandardPasses RegisterLogWritePass(PassManagerBuilder::EP_EarlyAsPossible, registerLogWritePass);
