#include "block_manage.h"
#include "types.h"
#include "statements.h"

#include <stdio.h>
#include <string.h>

#include "expressions.h"
#include "loop_context.h"
#include "utils.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "compiler-utils/ast/ast.h"

//============================Обработка операторов (statements)==========================

void visit_if_statement(CFGBuilderContext* ctx, TSNode node) {
    // Структура: if <expr> then <stmt> [else <stmt>] end

    // 1. Обрабатываем условие
    TSNode condition_node = ts_node_child_by_field_name(node, "condition", 9);
    char cond_var[64];
    Type* cond_type = eval_to_temp(ctx, condition_node, cond_var);
    // Проверяем, что условие типа bool
    if (cond_type->kind != TYPE_BOOL) {
        fprintf(stderr, "Ошибка: условие в if должно быть типа bool.\n");
        // Можно продолжить с заглушкой или остановиться
    }

    // 2. Создаём блоки
    BasicBlock* then_block = create_new_block(ctx);
    BasicBlock* else_block = create_new_block(ctx);
    BasicBlock* merge_block = create_new_block(ctx);

    if (!then_block || !else_block || !merge_block) {
        return; // ошибка выделения
    }

    // 3. Генерируем условный переход из текущего блока
    Operand cond_op = make_var_operand(cond_var, cond_type);
    emit_cond_br(ctx, cond_op, then_block->id, else_block->id);
    // 4. Обрабатываем тело then
    ctx->current_block = then_block;

    TSNode consequence = ts_node_child_by_field_name(node, "consequence", 11);
    if (!ts_node_is_null(consequence)) {
        visit_statement(ctx, consequence);
    }
    emit_jump(ctx, merge_block->id);
    // 5. Обрабатываем тело else (если есть)
    ctx->current_block = else_block;

    TSNode alternative = ts_node_child_by_field_name(node, "alternative", 11);
    if (!ts_node_is_null(alternative)) {
        visit_statement(ctx, alternative);
    }
    emit_jump(ctx, merge_block->id);
    // 6. Переключаемся на merge_block как текущий
    ctx->current_block = merge_block;
}

//Обрабатывает while и until (pre-test циклы).
void visit_loop_statement(CFGBuilderContext* ctx, TSNode node) {
    // Структура: (while|until) <expr> <statement>* end

    // 1. Определяем тип цикла: while или until
    TSNode keyword_node = ts_node_child_by_field_name(node, "keyword", 7);
    char keyword[16] = {0};
    if (!ts_node_is_null(keyword_node)) {
        get_node_text(keyword_node, ctx->source_code, keyword, sizeof(keyword));
    }

    bool is_until = (strcmp(keyword, "until") == 0);

    // 2. Обрабатываем условие
    TSNode condition_node = ts_node_child_by_field_name(node, "condition", 9);
    char cond_var[64];
    Type* cond_type = eval_to_temp(ctx, condition_node, cond_var);
    // Проверяем, что условие типа bool
    if (cond_type->kind != TYPE_BOOL) {
        fprintf(stderr, "Ошибка: условие в цикле должно быть типа bool.\n");
        // Можно продолжить с заглушкой или остановиться
    }
    // 3. Создаём блоки
    BasicBlock* header_block = create_new_block(ctx);  // проверка условия
    BasicBlock* body_block = create_new_block(ctx);    // тело цикла
    BasicBlock* exit_block = create_new_block(ctx);    // выход

    if (!header_block || !body_block || !exit_block) {
        return;
    }

    // 4. Безусловный переход в header из текущего блока
    emit_jump(ctx, header_block->id);
    // 5. Header: условный переход
    ctx->current_block = header_block;
    Operand cond_op = make_var_operand(cond_var, cond_type);
    if (is_until) {
        // until: повторять, пока условие ЛОЖНО → выход при true
        emit_cond_br(ctx, cond_op, exit_block->id, body_block->id);
    } else {
        // while: повторять, пока условие ИСТИННО → выход при false
        emit_cond_br(ctx, cond_op, body_block->id, exit_block->id);
    }
    // 6. Body: обрабатываем все statement'ы до 'end'
    ctx->current_block = body_block;
    visit_statements_with_break_context(ctx, node, 2, exit_block->id);
    emit_jump(ctx, header_block->id);
    // 7. Выход из цикла
    ctx->current_block = exit_block;
}

//Обрабатывает repeat... (post-test цикл).
void visit_repeat_statement(CFGBuilderContext* ctx, TSNode node) {
    // Структура: <statement> (while|until) <expr> ';'

    // 1. Определяем тип цикла: while или until
    TSNode keyword_node = ts_node_child_by_field_name(node, "keyword", 7);
    char keyword[16] = {0};
    if (!ts_node_is_null(keyword_node)) {
        get_node_text(keyword_node, ctx->source_code, keyword, sizeof(keyword));
    }
    bool is_until = (strcmp(keyword, "until") == 0);

    // 2. Находим тело цикла (первый ребёнок — statement)
    TSNode body_stmt = ts_node_child_by_field_name(node, "body", 4);
    if (ts_node_is_null(body_stmt)) {
        body_stmt = ts_node_child(node, 0); // fallback: первый ребёнок
    }

    // 3. Находим условие
    TSNode cond_expr = ts_node_child_by_field_name(node, "condition", 9);
    if (ts_node_is_null(cond_expr)) {
        // fallback: обычно на позиции 2 или 3
        uint32_t child_count = ts_node_child_count(node);
        for (uint32_t i = 0; i < child_count; i++) {
            TSNode child = ts_node_child(node, i);
            const char* type = ts_node_type(child);
            if (strcmp(type, "expr") == 0 ||
                strcmp(type, "binary_expr") == 0 ||
                strcmp(type, "identifier") == 0) {
                cond_expr = child;
                break;
            }
        }
    }

    if (ts_node_is_null(cond_expr)) {
        fprintf(stderr, "Ошибка: не найдено условие в repeat-цикле.\n");
        return;
    }

    // 4. Создаём блоки
    BasicBlock* body_block = create_new_block(ctx);
    BasicBlock* header_block = create_new_block(ctx);
    BasicBlock* exit_block = create_new_block(ctx);

    if (!body_block || !header_block || !exit_block) {
        return;
    }
    // 5. Безусловный переход в тело из текущего блока
    emit_jump(ctx, body_block->id);
    // 6. Обрабатываем тело
    ctx->current_block = body_block;
    visit_statements_with_break_context(ctx, node, 0, exit_block->id);
    // 7. Переход к заголовку (проверке условия)
    emit_jump(ctx, header_block->id);
    // 8. Header: вычисляем условие
    ctx->current_block = header_block;
    char cond_var[64];
    Type* cond_type = eval_to_temp(ctx, cond_expr, cond_var);
    // Проверяем, что условие типа bool
    if (cond_type->kind != TYPE_BOOL) {
        fprintf(stderr, "Ошибка: условие в repeat-цикле должно быть типа bool.\n");
        // Можно продолжить с заглушкой или остановиться
    }
    Operand cond_op = make_var_operand(cond_var, cond_type);
    if (is_until) {
        // repeat ... until cond; → выход при true
        emit_cond_br(ctx, cond_op, exit_block->id, body_block->id);
    } else {
        // repeat ... while cond; → выход при false
        emit_cond_br(ctx, cond_op, body_block->id, exit_block->id);
    }
    // 9. Выход из цикла
    ctx->current_block = exit_block;
}

// Генерирует IR_JUMP к текущему loop_exit (требует стека циклов).
void visit_break_statement(CFGBuilderContext* ctx, TSNode node) {
    // break_statement: 'break' ';'

    // 1. Проверяем, находимся ли мы внутри цикла
    if (ctx->loop_depth <= 0) {
        fprintf(stderr, "Ошибка: оператор 'break' вне цикла.\n");
        // Можно прервать компиляцию или проигнорировать
        return;
    }

    // 2. Получаем ID блока-выхода из стека
    const char* exit_block_id = ctx->loop_exit_stack[ctx->loop_depth - 1];

    // 3. Генерируем безусловный переход
    emit_jump(ctx, exit_block_id);
}

//Генерирует IR_RET (с выражением или без).
void visit_return_statement(CFGBuilderContext* ctx, TSNode node) {
    // return_statement: 'return' [expr] ';'

    // 1. Проверяем, есть ли выражение после 'return'
    TSNode expr_node = {0};
    bool has_expr = false;

    // В грамматике: seq('return', optional($.expr), ';')
    // Выражение — второй ребёнок (если есть)
    if (ts_node_child_count(node) >= 2) {
        expr_node = ts_node_child(node, 1);
        const char* expr_type = ts_node_type(expr_node);
        // Проверяем, что это не ';' (терминал)
        if (strcmp(expr_type, ";") != 0 && !ts_node_is_null(expr_node)) {
            has_expr = true;
        }
    }

    // 2. Случай: return без значения
    if (!has_expr) {
        // Функция должна возвращать void
        if (ctx->current_function->return_type->kind != TYPE_VOID) {
            fprintf(stderr, "Ошибка: функция '%s' должна возвращать значение, но используется 'return;'.\n",
                    ctx->current_function->name);
            // Можно продолжить с заглушкой или прервать
        }

        IRInstruction ret = {0};
        ret.opcode = IR_RET;
        ret.data.ret.has_value = false;
        emit_instruction(ctx, ret);
        return;
    }

    // 3. Случай: return expr;
    char result_var[64];
    Type* expr_type = eval_to_temp(ctx, expr_node, result_var);
    // Проверка: тип выражения должен соответствовать типу возврата функции
    if (ctx->current_function->return_type->kind == TYPE_VOID) {
        fprintf(stderr, "Ошибка: функция '%s' объявлена как void, но пытается вернуть значение.\n",
                ctx->current_function->name);
        // Можно проигнорировать или остановиться
    }
    // Дополнительно: проверка совпадения типов (упрощённо)
    else if (expr_type->kind != ctx->current_function->return_type->kind) {
        fprintf(stderr, "Ошибка: тип возвращаемого значения не совпадает с типом функции '%s'.\n",
                ctx->current_function->name);
        // Например: функция of int, а возвращается bool
    }

    // 4. Генерируем IR_RET с значением
    IRInstruction ret = {0};
    ret.opcode = IR_RET;
    ret.data.ret.has_value = true;
    ret.data.ret.value = make_var_operand(result_var, expr_type);
    emit_instruction(ctx, ret);
}

//Обрабатывает expr; — вызывает visit_expr с игнорированием результата или сохранением в _.
void visit_expression_statement(CFGBuilderContext* ctx, TSNode node) {
    // expression_statement: expr ';'

    // Выражение — первый ребёнок (до ';')
    const TSNode expr_node = ts_node_child(node, 0);
    if (ts_node_is_null(expr_node)) {
        return; // пустой оператор
    }

    const TSNode expression_node = ts_node_child(expr_node, 0);

    // Даже если результат не используется, выражение может иметь побочные эффекты
    // (например, вызов функции, присваивание)
    char dummy_result[64];
    eval_to_temp(ctx, expression_node, dummy_result);
}

// Обходит{ ... } или begin ... end — просто последовательность statement.
void visit_block_statement(CFGBuilderContext* ctx, const TSNode node) {
    // block_statement: (begin|{) (statement)* (end|})

    const uint32_t child_count = ts_node_child_count(node);

    // Пропускаем открывающую скобку/ключевое слово (первый ребёнок)
    // и закрывающую (последний ребёнок)
    // Обрабатываем всё, что между ними

    for (uint32_t i = 1; i < child_count - 1; i++) {
        TSNode stmt = ts_node_child(node, i);
        // Игнорируем закрывающий токен (на случай, если он попал внутрь)
        const char* stmt_type = ts_node_type(stmt);
        if (strcmp(stmt_type, "end") == 0 || strcmp(stmt_type, "}") == 0) {
            break;
        }
        visit_statement(ctx, stmt);
    }
}

//Диспетчер: вызывает нужную функцию в зависимости от типа узла (if_statement, loop_statement, и т.д.).
void visit_statement(CFGBuilderContext* ctx, const TSNode node) {
    const char* node_type = ts_node_type(node);

    if (strcmp(node_type, "statement") == 0) {

        //У statement есть дочерний элемент, который и является выражением, которое мы должны разобрать
        const TSNode first_children = ts_node_child(node, 0);

        visit_statement(ctx, first_children);
    }

    if (strcmp(node_type, "if_statement") == 0) {
        visit_if_statement(ctx, node);
    }
    else if (strcmp(node_type, "loop_statement") == 0) {
        visit_loop_statement(ctx, node);
    }
    else if (strcmp(node_type, "repeat_statement") == 0) {
        visit_repeat_statement(ctx, node);
    }
    else if (strcmp(node_type, "break_statement") == 0) {
        visit_break_statement(ctx, node);
    }
    else if (strcmp(node_type, "return_statement") == 0) {
        visit_return_statement(ctx, node);
    }
    else if (strcmp(node_type, "expression_statement") == 0) {
        visit_expression_statement(ctx, node);
    }
    else if (strcmp(node_type, "block_statement") == 0) {
        visit_block_statement(ctx, node);
    }
    else {
        // Неизвестный тип — игнорируем или выводим предупреждение
        // Например, пустой statement
    }
}



