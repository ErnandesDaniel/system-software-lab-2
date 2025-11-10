

#include "types.h"
#include "loop_context.h"

#include <string.h>

#include "statements.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

// =================================Контекст циклов (для break)========

// При входе в цикл.
void push_loop_exit(CFGBuilderContext* ctx, const char* exit_id) {
    if (ctx->loop_depth < 32) {
        strcpy(ctx->loop_exit_stack[ctx->loop_depth], exit_id);
        ctx->loop_depth++;
    }
}

// При выходе из цикла.
void pop_loop_exit(CFGBuilderContext* ctx) {
    if (ctx->loop_depth > 0) ctx->loop_depth--;
}

//Для break
const char* current_loop_exit(CFGBuilderContext* ctx) {
    return (ctx->loop_depth > 0) ? ctx->loop_exit_stack[ctx->loop_depth - 1] : NULL;
}

//обрабатывает последовательность операторов (statement'ов) внутри цикла, временно добавляя точку выхода в стек циклов, чтобы break знал, куда прыгать.
void visit_statements_with_break_context(CFGBuilderContext* ctx, TSNode parent, uint32_t start_idx, const char* exit_id) {
    push_loop_exit(ctx, exit_id);
    uint32_t count = ts_node_child_count(parent);
    for (uint32_t i = start_idx; i < count; i++) {
        TSNode stmt = ts_node_child(parent, i);
        if (strcmp(ts_node_type(stmt), "end") == 0) break;
        visit_statement(ctx, stmt);
    }
    pop_loop_exit(ctx);
}


