#ifndef CFG_EXPRESSION_H
#define CFG_EXPRESSION_H

#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

#include "types.h"
// Обработка выражений
Type* visit_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);
Type* visit_binary_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);
Type* visit_unary_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);
Type* visit_parenthesized_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);
Type* visit_call_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);
Type* visit_slice_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);
Type* visit_identifier_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);
Type* visit_literal_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);


// Вспомогательные функции
Operand make_var_operand(const char* name, Type* type);
Operand make_const_operand_int(int64_t val);
Operand make_const_operand_bool(bool val);
Operand make_const_operand_string(const char* str);

#endif




