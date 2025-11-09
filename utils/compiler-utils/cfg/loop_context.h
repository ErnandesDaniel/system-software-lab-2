
#ifndef CFG_LOOP_CONTEXT_H
#define CFG_LOOP_CONTEXT_H

#include "types.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

void push_loop_exit(CFGBuilderContext* ctx, const char* exit_id);
void pop_loop_exit(CFGBuilderContext* ctx);
const char* current_loop_exit(CFGBuilderContext* ctx);
void visit_statements_with_break_context(CFGBuilderContext* ctx, TSNode parent, uint32_t start_idx, const char* exit_id);

#endif

