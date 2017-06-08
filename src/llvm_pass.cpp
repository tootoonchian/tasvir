#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
struct TasvirPass : public FunctionPass {
    static char ID;
    TasvirPass() : FunctionPass(ID) {}

    bool runOnFunction(Function &f) override {
        const DataLayout &layout = f.getParent()->getDataLayout();
        LLVMContext &ctx = f.getContext();
        Constant *logFunc = f.getParent()->getOrInsertFunction("tasvir_log_write", Type::getVoidTy(ctx), Type::getInt8PtrTy(ctx),
                                                               Type::getInt64Ty(ctx), NULL);

        for (auto &block : f) {
            for (auto &inst : block) {
                Value *dst;
                Value *len;
                if (isa<CallInst>(inst)) {
                    /*
                    Value *callee = inst.getOperand(inst.getNumOperands() - 1);
                    if(callee->getName().str() != "llvm.var.annotation")
                        continue;
                    Value *annotatedValue = inst.getOperand(0);
                    if(annotatedValue->getValueID() != Value::InstructionVal + Instruction::BitCast)
                        continue;
                    Argument *a = mapValueToArgument[annotatedValue->getUnderlyingObject()];
                    if(!a)
                        continue;

                    Value *annotation = inst.getOperand(1);
                    if(annotation->getValueID() != Value::ConstantExprVal)
                        continue;
                    ConstantExpr *ce = (ConstantExpr *)annotation;
                    if(ce->getOpcode() != Instruction::GetElementPtr)
                        continue;

                    // `ConstantExpr` operands: http://llvm.org/docs/LangRef.html#constantexprs
                    Value *gv = ce->getOperand(0);

                    if(gv->getValueID() != Value::GlobalVariableVal)
                        continue;

                    Value *v = module->getNamedValue(gv->getName().str())->getOperand(0);
                    assert (v->getValueID() == Value::ConstantArrayVal);
                    ConstantArray *ca = (ConstantArray *)v;
                    std::string annotation_str = ca->getAsString();
                    std::cout << "    argument " << a->getType()->getDescription() << " " << a->getName().str()
                        << " has annotation \"" << getGlobalVariableString(gv->getName().str()) << "\"\n";
                    */
                } else if (isa<StoreInst>(inst) || isa<AtomicRMWInst>(inst)) {
                    dst = inst.getOperand(1);
                    len = ConstantInt::get(Type::getInt64Ty(ctx), layout.getTypeAllocSize(dst->getType()));
                } else if (isa<AtomicCmpXchgInst>(inst)) {
                    dst = inst.getOperand(0);
                    len = ConstantInt::get(Type::getInt64Ty(ctx), layout.getTypeAllocSize(dst->getType()));
                } else if (isa<MemIntrinsic>(inst)) {
                    auto *op = dyn_cast<MemIntrinsic>(&inst);
                    dst = op->getDest();
                    len = op->getLength();
                } else {
                    continue;
                }
                if (isa<AllocaInst>(dst))
                    continue;

                // Insert *after* `op`.
                IRBuilder<> builder(&inst);
                builder.SetInsertPoint(&block, ++builder.GetInsertPoint());
                Value *args[] = {dst, len};
                builder.CreateCall(logFunc, args);
                errs() << inst << "\n\t";
                errs().write_escaped(inst.getOpcodeName())
                    << " *dst:" << *dst << " type:" << *dst->getType() << " len:" << *len << "\n";
            }
        }

        return false;
    }

};  // end of struct TasvirPass
}  // end of anonymous namespace

char TasvirPass::ID = 0;
static RegisterPass<TasvirPass> X("tasvir_pass", "Tasvir Instrumentation Pass", false /* Only looks at CFG */,
                                  false /* Analysis Pass */);

static void registerTasvirPass(const PassManagerBuilder &, legacy::PassManagerBase &PM) { PM.add(new TasvirPass()); }
static RegisterStandardPasses RegisterTasvirPass(PassManagerBuilder::EP_EarlyAsPossible, registerTasvirPass);
