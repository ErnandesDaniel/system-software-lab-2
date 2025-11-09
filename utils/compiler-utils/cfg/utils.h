
#ifndef CFG_UTILS_H
#define CFG_UTILS_H

#include "types.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

Type* ensure_bool_expr(CFGBuilderContext* ctx, TSNode expr, char* result_var);
Type* eval_to_temp(CFGBuilderContext* ctx, TSNode expr, char* out_temp);
void generate_temp_name(CFGBuilderContext* ctx, char* buffer, const size_t buffer_size);

#endif