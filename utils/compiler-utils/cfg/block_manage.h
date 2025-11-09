
#ifndef CFG_BLOCK_MANAGE_H
#define CFG_BLOCK_MANAGE_H

#include "types.h"

BasicBlock* create_new_block(CFGBuilderContext* ctx);

void add_successor(BasicBlock* block, const char* target_id);
void emit_jump(CFGBuilderContext* ctx, const char* target);
void emit_cond_br(CFGBuilderContext* ctx, Operand cond, const char* true_target, const char* false_target);
void emit_instruction(const CFGBuilderContext* ctx, const IRInstruction inst);

#endif
