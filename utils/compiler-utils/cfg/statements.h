
#ifndef CFG_STATEMENT_H
#define CFG_STATEMENT_H

#include "types.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

// Обработка операторов
void visit_statement(CFGBuilderContext* ctx, TSNode node);
void visit_if_statement(CFGBuilderContext* ctx, TSNode node);
void visit_loop_statement(CFGBuilderContext* ctx, TSNode node);
void visit_repeat_statement(CFGBuilderContext* ctx, TSNode node);
void visit_break_statement(CFGBuilderContext* ctx, TSNode node);
void visit_return_statement(CFGBuilderContext* ctx, TSNode node);
void visit_expression_statement(CFGBuilderContext* ctx, TSNode node);
void visit_block_statement(CFGBuilderContext* ctx, TSNode node);

#endif
