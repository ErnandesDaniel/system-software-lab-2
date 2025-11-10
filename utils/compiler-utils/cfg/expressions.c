


#include "types.h"
#include "expressions.h"

#include <stdio.h>
#include <string.h>

#include "block_manage.h"
#include "utils.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "compiler-utils/ast/ast.h"

//=====================Вспомогательные функции для выражений============================


// Создаёт OPERAND_VAR
Operand make_var_operand(const char* name, Type* type) {
    Operand op = {0};
    op.kind = OPERAND_VAR;
    if (name) {
        op.data.var.name = strdup(name); // или выдели в пуле
    } else {
        op.data.var.name = NULL;
    }
    op.data.var.type = type;
    return op;
}

// Создаёт OPERAND_CONST для целых чисел
Operand make_const_operand_int(int64_t val) {
    Operand op = {0};
    op.kind = OPERAND_CONST;
    op.data.const_val.type = make_int_type();
    op.data.const_val.value.integer = (int32_t)val; // или int64_t, если ConstValue поддерживает
    return op;
}

// Для true/false
Operand make_const_operand_bool(bool val) {
    Operand op = {0};
    op.kind = OPERAND_CONST;
    op.data.const_val.type = make_bool_type();
    op.data.const_val.value.integer = val ? 1 : 0;
    return op;
}

// Для строковых литералов
Operand make_const_operand_string(const char* str) {
    Operand op = {0};
    op.kind = OPERAND_CONST;
    op.data.const_val.type = make_string_type();
    if (str) {
        op.data.const_val.value.string = strdup(str); // важно: strdup!
    } else {
        op.data.const_val.value.string = strdup("");
    }
    return op;
}



//=========================================Обработка выражений (expressions)=============


//Обрабатывает a + b,x && y и т.д.
Type* visit_binary_expr(CFGBuilderContext* ctx, TSNode node, char* result_var){
    // Получаем операнды и оператор
    TSNode left = ts_node_child(node, 0);
    TSNode op = ts_node_child(node, 1);
    TSNode right = ts_node_child(node, 2);

    char op_text[16];
    get_node_text(op, ctx->source_code, op_text, sizeof(op_text));

    // Обрабатываем присваивание отдельно (оно не вычисляет новое значение, а меняет переменную)
    if (strcmp(op_text, "=") == 0) {

        const char* left_type=ts_node_type(left);

        // Левый операнд должен быть идентификатором
        if (strcmp(left_type, "expr") != 0) {
            fprintf(stderr, "Error: left operand of assignment must be an expr->identifier.\n");
        }

        TSNode left_expr_child_node = ts_node_child(left, 0);

        const char* left_expr_child_node_type=ts_node_type(left_expr_child_node);

        // Левый операнд должен быть идентификатором
        if (strcmp(left_expr_child_node_type, "identifier") != 0) {
            fprintf(stderr, "Error: left operand of assignment must be an identifier.\n");
        }

        char var_name[64];
        get_node_text(left_expr_child_node, ctx->source_code, var_name, sizeof(var_name));

        // Обрабатываем правый операнд
        char right_temp[64];
        Type* right_type = eval_to_temp(ctx, right, right_temp);

        // Добавляем переменную в локальную область (если новая)
        Symbol* existing = symbol_table_lookup(&ctx->local_vars, var_name);


        if (!existing) {
            // Новая переменная — тип выводится из правого операнда
            symbol_table_add(&ctx->local_vars, var_name, right_type);
        }
        // Если переменная уже есть — тип не меняем (можно добавить проверку совместимости)

        // Генерируем IR_ASSIGN
        IRInstruction assign = {0};
        assign.opcode = IR_ASSIGN;
        strcpy(assign.data.assign.target, var_name);
        assign.data.assign.value = make_var_operand(right_temp, right_type);
        emit_instruction(ctx, assign);
        // Результат присваивания — значение справа (как в C)
        strcpy(result_var, right_temp);
        return right_type;
    }

    // === Все остальные операторы: вычисляют новое значение ===

    // Обрабатываем левый и правый операнды
    char left_temp[64], right_temp[64];
    Type* left_type = eval_to_temp(ctx, left, left_temp);
    Type* right_type = eval_to_temp(ctx, right, right_temp);
    // Определяем opcode и результирующий тип
    IROpcode opcode = IR_ADD; // заглушка
    Type* result_type = make_int_type();

    // Арифметические операции
    if (strcmp(op_text, "+") == 0 || strcmp(op_text, "-") == 0 ||
        strcmp(op_text, "*") == 0 || strcmp(op_text, "/") == 0 ||
        strcmp(op_text, "%") == 0) {

        opcode =
            (strcmp(op_text, "+") == 0) ? IR_ADD :
            (strcmp(op_text, "-") == 0) ? IR_SUB :
            (strcmp(op_text, "*") == 0) ? IR_MUL :
            (strcmp(op_text, "/") == 0) ? IR_DIV : IR_ADD; // % → можно добавить IR_MOD

        result_type = make_int_type();
    }
    // Операции сравнения → всегда bool
    else if (strcmp(op_text, "==") == 0 || strcmp(op_text, "!=") == 0 ||
             strcmp(op_text, "<") == 0 || strcmp(op_text, ">") == 0 ||
             strcmp(op_text, "<=") == 0 || strcmp(op_text, ">=") == 0) {
        opcode =
            (strcmp(op_text, "==") == 0) ? IR_EQ :
            (strcmp(op_text, "!=") == 0) ? IR_NE :
            (strcmp(op_text, "<") == 0) ? IR_LT :
            (strcmp(op_text, ">") == 0) ? IR_GT :
            (strcmp(op_text, "<=") == 0) ? IR_LE : IR_GE;
        result_type = make_bool_type();
    }
    // Логические операции (требуют bool-операндов)
    else if (strcmp(op_text, "&&") == 0) {
        opcode = IR_AND;
        result_type = make_bool_type();
        if (left_type->kind != TYPE_BOOL || right_type->kind != TYPE_BOOL) {
            fprintf(stderr, "Предупреждение: операнды '&&' должны быть bool.\n");
        }
    }
    else if (strcmp(op_text, "||") == 0) {
        opcode = IR_OR;
        result_type = make_bool_type();
        if (left_type->kind != TYPE_BOOL || right_type->kind != TYPE_BOOL) {
            fprintf(stderr, "Предупреждение: операнды '||' должны быть bool.\n");
        }
    }
    else {
        fprintf(stderr, "Неизвестный бинарный оператор: '%s'\n", op_text);
        return make_int_type();
    }
    // Генерируем вычисляющую инструкцию
    IRInstruction compute = {0};
    compute.opcode = opcode;
    strcpy(compute.data.compute.result, result_var);
    compute.data.compute.result_type = result_type;
    compute.data.compute.operands[0] = make_var_operand(left_temp, left_type);
    compute.data.compute.operands[1] = make_var_operand(right_temp, right_type);
    compute.data.compute.num_operands = 2;
    emit_instruction(ctx, compute);



    return result_type;
}

//Обрабатывает-x,!flag,~mask.
Type* visit_unary_expr(CFGBuilderContext* ctx, TSNode node, char* result_var) {
    // unary_expr: (оператор) (операнд)

    TSNode op_node = ts_node_child(node, 0);
    TSNode operand_node = ts_node_child(node, 1);

    char op_text[8];
    get_node_text(op_node, ctx->source_code, op_text, sizeof(op_text));

    // Обрабатываем операнд
    char operand_temp[64];
    Type* operand_type = eval_to_temp(ctx, operand_node, operand_temp);
    // Определяем opcode и результирующий тип
    IROpcode opcode = IR_NEG; // заглушка
    Type* result_type = operand_type; // по умолчанию тот же тип

    if (strcmp(op_text, "-") == 0) {
        opcode = IR_NEG;
        result_type = make_int_type(); // унарный минус → int
    }
    else if (strcmp(op_text, "+") == 0) {
        opcode = IR_POS;
        result_type = make_int_type(); // унарный плюс → int (обычно no-op)
    }
    else if (strcmp(op_text, "!") == 0) {
        opcode = IR_NOT;
        result_type = make_bool_type(); // логическое НЕ → bool
        // Проверка: операнд должен быть bool (опционально)
        if (operand_type->kind != TYPE_BOOL) {
            fprintf(stderr, "Предупреждение: операнд '!' должен быть bool.\n");
        }
    }
    else if (strcmp(op_text, "~") == 0) {
        opcode = IR_BIT_NOT;
        result_type = make_int_type(); // побитовое НЕ → int
    }
    else {
        fprintf(stderr, "Неизвестный унарный оператор: '%s'\n", op_text);
        return make_int_type();
    }

    // Генерируем унарную инструкцию
    IRInstruction unary = {0};
    unary.opcode = opcode;
    strcpy(unary.data.unary.result, result_var);
    unary.data.unary.result_type = result_type;
    unary.data.unary.operand = make_var_operand(operand_temp, operand_type);
    emit_instruction(ctx, unary);
    return result_type;
}

//Просто делегирует visit_expr внутреннему выражению.
Type* visit_parenthesized_expr(CFGBuilderContext* ctx, TSNode node, char* result_var) {
    // parenthesized_expr: '(' expr ')'

    // Внутреннее выражение — первый именованный ребёнок
    TSNode inner_expr = ts_node_named_child(node, 0);

    // Если именованных детей нет — берём первый обычный (обычно на позиции 1)
    if (ts_node_is_null(inner_expr)) {
        if (ts_node_child_count(node) >= 3) {
            inner_expr = ts_node_child(node, 1); // пропускаем '(' и берём expr
        } else {
            // Ошибка: нет внутреннего выражения
            fprintf(stderr, "Ошибка: пустые скобки ().\n");
            return make_int_type(); // заглушка
        }
    }

    // Просто делегируем обработку внутреннему выражению
    return visit_expr(ctx, inner_expr, result_var);
}

//Обрабатывает f(a, b)→ генерирует IR_CALL.
Type* visit_call_expr(CFGBuilderContext* ctx, TSNode node, char* result_var) {
    // call_expr: function '(' [arguments] ')'

    // 1. Получаем узел функции (обычно identifier)
    TSNode func_expr = ts_node_child_by_field_name(node, "function", 8);
    if (ts_node_is_null(func_expr)) {
        func_expr = ts_node_child(node, 0); // fallback
    }

    // Функция должна быть идентификатором
    if (strcmp(ts_node_type(func_expr), "identifier") != 0) {
        fprintf(stderr, "Ошибка: вызываемое выражение должно быть идентификатором функции.\n");
        return make_int_type(); // заглушка
    }

    char func_name[64];
    get_node_text(func_expr, ctx->source_code, func_name, sizeof(func_name));

    // 2. Находим информацию о функции
    FunctionInfo* callee = find_function(func_name);
    if (!callee) {
        fprintf(stderr, "Ошибка: функция '%s' не объявлена.\n", func_name);
        return make_int_type();
    }

    // 3. Обрабатываем аргументы
    Operand args[16] = {0}; // максимум 16 аргументов
    int num_args = 0;

    TSNode args_node = ts_node_child_by_field_name(node, "arguments", 9);
    if (!ts_node_is_null(args_node)) {
        // list_expr: expr (',' expr)*
        uint32_t child_count = ts_node_child_count(args_node);
        for (uint32_t i = 0; i < child_count && num_args < 16; i++) {
            TSNode arg_expr = ts_node_child(args_node, i);
            // Пропускаем запятые (терминалы)
            if (ts_node_is_named(arg_expr)) {
                char arg_temp[64];
                Type* arg_type = eval_to_temp(ctx, arg_expr, arg_temp);
                args[num_args] = make_var_operand(arg_temp, arg_type);
                num_args++;
            }
        }
    }

    // 4. Проверка количества аргументов (опционально)
    if (num_args != callee->params.count) {
        fprintf(stderr, "Предупреждение: функция '%s' вызвана с %d аргументами, но ожидает %d.\n",
                func_name, num_args, callee->params.count);
        // Можно продолжить или остановиться
    }

    // 5. Генерируем IR_CALL
    IRInstruction call = {0};
    call.opcode = IR_CALL;
    strcpy(call.data.call.result, result_var);
    call.data.call.result_type = callee->return_type;
    strcpy(call.data.call.func_name, func_name);

    for (int i = 0; i < num_args; i++) {
        call.data.call.args[i] = args[i];
    }
    call.data.call.num_args = num_args;

    emit_instruction(ctx, call);
    return callee->return_type;
}

//Доступ к массиву:arr[i]
Type* visit_slice_expr(CFGBuilderContext* ctx, TSNode node, char* result_var) {
    // slice_expr: array '[' [ranges] ']'

    // 1. Обрабатываем выражение массива
    TSNode array_expr = ts_node_child_by_field_name(node, "array", 5);
    if (ts_node_is_null(array_expr)) {
        array_expr = ts_node_child(node, 0);
    }

    char array_name[64];
    Type* array_type = eval_to_temp(ctx, array_expr, array_name);
    // Проверка: должно быть массивом
    if (!array_type || array_type->kind != TYPE_ARRAY) {
        fprintf(stderr, "Ошибка: попытка доступа к не-массиву.\n");
        return make_int_type(); // заглушка
    }

    Type* element_type = array_type->data.array_info.element_type;
    if (!element_type) {
        element_type = make_int_type();
    }

    // 2. Получаем ranges
    TSNode ranges_node = ts_node_child_by_field_name(node, "ranges", 6);
    if (ts_node_is_null(ranges_node)) {
        fprintf(stderr, "Ошибка: пустой индекс в доступе к массиву.\n");
        return element_type;
    }

    // Поддерживаем только первый диапазон (одномерный доступ)
    TSNode first_range = {0};
    uint32_t range_child_count = ts_node_child_count(ranges_node);
    for (uint32_t i = 0; i < range_child_count; i++) {
        TSNode child = ts_node_child(ranges_node, i);
        if (ts_node_is_named(child) && strcmp(ts_node_type(child), "range") == 0) {
            first_range = child;
            break;
        }
    }

    if (ts_node_is_null(first_range)) {
        fprintf(stderr, "Ошибка: некорректный индекс.\n");
        return element_type;
    }

    // 3. Обрабатываем начало диапазона (обязательно)
    TSNode start_expr = ts_node_child_by_field_name(first_range, "start", 5);
    if (ts_node_is_null(start_expr)) {
        fprintf(stderr, "Ошибка: отсутствует начальный индекс.\n");
        return element_type;
    }

    char start_index[64];
    Type* start_type = eval_to_temp(ctx, start_expr, start_index);
    // Проверка: индекс должен быть целым
    if (start_type->kind != TYPE_INT) {
        fprintf(stderr, "Предупреждение: индекс должен быть целым числом.\n");
    }

    // 4. Проверяем, есть ли конец диапазона
    TSNode end_expr = ts_node_child_by_field_name(first_range, "end", 3);

    if (ts_node_is_null(end_expr)) {
        // === Одиночный элемент: arr[i] ===
        IRInstruction load = {0};
        load.opcode = IR_LOAD;
        strcpy(load.data.load.result, result_var);
        load.data.load.result_type = element_type;
        strcpy(load.data.load.array, array_name);
        strcpy(load.data.load.index, start_index);
        emit_instruction(ctx, load);
        return element_type;
    } else {
        // === Срез: arr[i..j] ===
        char end_index[64];
        Type* end_type = eval_to_temp(ctx, end_expr, end_index);
        if (end_type->kind != TYPE_INT) {
            fprintf(stderr, "Предупреждение: конечный индекс должен быть целым.\n");
        }

        // Тип среза — тот же массивный тип, но, возможно, другого размера
        // Для простоты пока возвращаем тот же element_type (можно улучшить позже)
        IRInstruction slice = {0};
        slice.opcode = IR_SLICE;
        strcpy(slice.data.slice.result, result_var);
        slice.data.slice.result_type = element_type; // или make_array_type(element_type, 0)
        strcpy(slice.data.slice.array, array_name);
        strcpy(slice.data.slice.start, start_index);
        strcpy(slice.data.slice.end, end_index);
        slice.data.slice.has_end = true;
        emit_instruction(ctx, slice);
        return element_type;
    }
}

//Копирует имя идентификатора в result_var
Type* visit_identifier_expr(CFGBuilderContext* ctx, TSNode node, char* result_var) {
    // identifier: [a-zA-Z_][a-zA-Z0-9_]*

    // 1. Извлекаем имя идентификатора
    char name[64];
    get_node_text(node, ctx->source_code, name, sizeof(name));

    // 2. Ищем переменную в локальной области видимости
    Symbol* sym = symbol_table_lookup(&ctx->local_vars, name);

    if (!sym) {
        // Переменная не найдена — ошибка
        fprintf(stderr, "Error: unknown variable '%s'.\n", name);

        // Заглушка: создаём временную переменную с типом int
        // (чтобы не сломать генерацию IR)
        symbol_table_add(&ctx->local_vars, name, make_int_type());
        sym = symbol_table_lookup(&ctx->local_vars, name);
    }

    // 3. Копируем имя в result_var (значение переменной — это её имя)
    strcpy(result_var, name);

    // 4. Возвращаем тип
    return sym->type;
}

//Преобразует литерал в константу → генерирует временную переменную с IR_ASSIGN константы.
Type* visit_literal_expr(CFGBuilderContext* ctx, TSNode node, char* result_var) {

    const TSNode literal_node=ts_node_child(node, 0);

    const char* literal_type = ts_node_type(literal_node);

    char literal_text[256];
    get_node_text(literal_node, ctx->source_code, literal_text, sizeof(literal_text));

    // === Целочисленные литералы ===
    if (strcmp(literal_type, "dec") == 0 ||
        strcmp(literal_type, "hex") == 0 ||
        strcmp(literal_type, "bits") == 0 ||
        strcmp(literal_type, "char") == 0) {

        // Преобразуем в число
        int64_t value = 0;
        if (strcmp(literal_type, "dec") == 0) {
            value = strtoll(literal_text, NULL, 10);
        }
        else if (strcmp(literal_type, "hex") == 0) {
            // Убираем 0x/0X
            const char* num_start = literal_text;
            if (strncmp(literal_text, "0x", 2) == 0 || strncmp(literal_text, "0X", 2) == 0) {
                num_start += 2;
            }
            value = strtoll(num_start, NULL, 16);
        }
        else if (strcmp(literal_type, "bits") == 0) {
            // Убираем 0b/0B
            const char* num_start = literal_text;
            if (strncmp(literal_text, "0b", 2) == 0 || strncmp(literal_text, "0B", 2) == 0) {
                num_start += 2;
            }
            value = strtoll(num_start, NULL, 2);
        }
        else if (strcmp(literal_type, "char") == 0) {
            // 'c' → извлекаем символ между кавычками
            if (strlen(literal_text) >= 3) {
                value = (unsigned char)literal_text[1];
            }
        }

        // Генерируем временную переменную и IR_ASSIGN с константой
        IRInstruction assign = {0};
        assign.opcode = IR_ASSIGN;
        strcpy(assign.data.assign.target, result_var);
        assign.data.assign.value = make_const_operand_int(value);
        emit_instruction(ctx, assign);

        return make_int_type();
    }

    // === Булевы литералы ===
    else if (strcmp(literal_type, "bool") == 0) {
        bool value = (strcmp(literal_text, "true") == 0);
        IRInstruction assign = {0};
        assign.opcode = IR_ASSIGN;
        strcpy(assign.data.assign.target, result_var);
        assign.data.assign.value = make_const_operand_bool(value);
        emit_instruction(ctx, assign);
        return make_bool_type();
    }

    // === Строковые литералы ===
    else if (strcmp(literal_type, "str") == 0) {
        // Удаляем внешние кавычки и обрабатываем экранирование (упрощённо)
        char* unquoted = malloc(strlen(literal_text) + 1);
        if (unquoted) {
            size_t len = strlen(literal_text);
            if (len >= 2) {
                // Копируем без первых и последних кавычек
                strncpy(unquoted, literal_text + 1, len - 2);
                unquoted[len - 2] = '\0';

                // TODO: обработка экранирования (\n, \", \\ и т.д.)
                // Для MVP просто удалим кавычки
            } else {
                unquoted[0] = '\0';
            }
        } else {
            unquoted = strdup("");
        }

        IRInstruction assign = {0};
        assign.opcode = IR_ASSIGN;
        strcpy(assign.data.assign.target, result_var);
        assign.data.assign.value = make_const_operand_string(unquoted);
        emit_instruction(ctx, assign);

        free(unquoted);
        return make_string_type();
    }

    // === Неизвестный литерал - ошибка===
    else {
        fprintf(stderr, "Critical error: unknown literal '%s' (type: %s).\n");
        exit(1);
    }
}

//Главный диспетчер выражений — вызывает нужный обработчик по типу
Type* visit_expr(CFGBuilderContext* ctx, const TSNode node, char* result_var) {
    const char* node_type = ts_node_type(node);

    if (strcmp(node_type, "expr") == 0) {

        //У expr есть дочерний элемент, который и является выражением, которое мы должны разобрать
        const TSNode first_children = ts_node_child(node, 0);

        return visit_expr(ctx, first_children, result_var);
    }

    // Бинарные операции: a + b, x && y, x = 5 и т.д.
    if (strcmp(node_type, "binary_expr") == 0) {
        return visit_binary_expr(ctx, node, result_var);
    }
    // Унарные операции: -x, !flag, ~mask
    else if (strcmp(node_type, "unary_expr") == 0) {
        return visit_unary_expr(ctx, node, result_var);
    }
    // Скобки: (expr)
    else if (strcmp(node_type, "parenthesized_expr") == 0) {
        return visit_parenthesized_expr(ctx, node, result_var);
    }
    // Вызов функции: foo(a, b)
    else if (strcmp(node_type, "call_expr") == 0) {
        return visit_call_expr(ctx, node, result_var);
    }
    // Доступ к массиву: arr[i] или arr[i..j]
    else if (strcmp(node_type, "slice_expr") == 0) {
        return visit_slice_expr(ctx, node, result_var);
    }
    // Идентификатор: x, temp, result
    else if (strcmp(node_type, "identifier") == 0) {
        return visit_identifier_expr(ctx, node, result_var);
    }

    // Литералы: 42, "hello", true, 0xFF
    else if (strcmp(node_type, "literal") == 0) {
        return  visit_literal_expr(ctx, node, result_var);
    } else{
        fprintf(stderr, "Unidentifiable expression");
    }
}

