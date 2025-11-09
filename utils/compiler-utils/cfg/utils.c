
#include <stdio.h>
#include "types.h"
#include "utils.h"

#include "expressions.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

// Генерация имени переменной вида "t42"
void generate_temp_name(CFGBuilderContext* ctx, char* buffer, const size_t buffer_size) {

    if (buffer_size == 0) return;

    snprintf(buffer, buffer_size, "t%d", ctx->temp_counter++);
}

// Проверка bool в условных выражениях
Type* ensure_bool_expr(CFGBuilderContext* ctx, TSNode expr, char* result_var) {
    Type* t = visit_expr(ctx, expr, result_var);
    if (t->kind != TYPE_BOOL) {
        fprintf(stderr, "Ошибка: выражение должно быть типа bool.\n");
        exit(1);
    }
    return t;
}

// вычисляет выражение и сохраняет его результат во временную переменную, имя которой возвращается в out_temp
Type* eval_to_temp(CFGBuilderContext* ctx, TSNode expr, char* out_temp) {
    generate_temp_name(ctx, out_temp, 64);
    return visit_expr(ctx, expr, out_temp);
}



