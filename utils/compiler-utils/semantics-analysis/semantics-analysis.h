#ifndef SEMANTICS_H
#define SEMANTICS_H

#include "../lib/tree-sitter/lib/include/tree_sitter/api.h"

// Основная точка входа: пройти AST и заполнить глобальные таблицы
void build_global_symbol_table(TSNode root, const char* source_code);

// (опционально) Вывод типа выражения — пока можешь закомментировать
// Type* infer_expr_type(TSNode expr, SymbolTable* local_scope, const char* source);

#endif // SEMANTICS_H





