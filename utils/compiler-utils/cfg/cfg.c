#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "../src/tree_sitter/parser.h"

#include "cfg.h"

#include "compiler-utils/ast/ast.h"
#include "compiler-utils/semantics-analysis/functions/functions.h"

TSLanguage *tree_sitter_mylang(); // Объявляем функцию из parser.c

// Вспомогательная структура контекста построения графа потока управления
typedef struct CFGBuilderContext {

    CFG* cfg; // Ссылка на текущий объект графа управления

    BasicBlock* current_block; //Ссылка на текущий обрабатываемый блок

    const char* source_code;   // исходный текст всего файла с кодом

    int temp_counter;   //Счётчик для генерации уникальных временных имён переменных (имен типа t0, t1, t2...)

    int block_counter;  // Счётчик для генерации уникальных имён базовых блоков (имен типа BB_0, BB_1...)

    // Для break
    BlockId loop_exit_stack[32];

    int loop_depth;

    // Информация о текущей функции (из symbol table)
    FunctionInfo* current_function;

    // Локальные переменные текущей функции
    SymbolTable local_vars;

} CFGBuilderContext;

// ==================== Прототипы всех функций ====================

// Обработка операторов
void visit_statement(CFGBuilderContext* ctx, TSNode node);
void visit_if_statement(CFGBuilderContext* ctx, TSNode node);
void visit_loop_statement(CFGBuilderContext* ctx, TSNode node);
void visit_repeat_statement(CFGBuilderContext* ctx, TSNode node);
void visit_break_statement(const CFGBuilderContext* ctx, TSNode node);
void visit_return_statement(CFGBuilderContext* ctx, TSNode node);
void visit_expression_statement(CFGBuilderContext* ctx, TSNode node);
void visit_block_statement(CFGBuilderContext* ctx, TSNode node);

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

void push_loop_exit(CFGBuilderContext* ctx, const char* exit_id);
void pop_loop_exit(CFGBuilderContext* ctx);
const char* current_loop_exit(CFGBuilderContext* ctx);

void add_successor(BasicBlock* block, const char* target_id);
void emit_jump(CFGBuilderContext* ctx, const char* target);
void emit_cond_br(CFGBuilderContext* ctx, Operand cond, const char* true_target, const char* false_target);

void visit_source_item(CFGBuilderContext* ctx, TSNode node);

// ===============================================================

//Добавление инструкции в текущий блок
void emit_instruction(const CFGBuilderContext* ctx, const IRInstruction inst) {

    if (!ctx->current_block) return;

    if (ctx->current_block->num_instructions >= MAX_INSTRUCTIONS) {
        // ошибка
        return;
    }
    ctx->current_block->instructions[ctx->current_block->num_instructions] = inst;

    ctx->current_block->num_instructions++;
}

// Генерация имени переменной вида "t42"
void generate_temp_name(CFGBuilderContext* ctx, char* buffer, const size_t buffer_size) {

    if (buffer_size == 0) return;

    snprintf(buffer, buffer_size, "t%d", ctx->temp_counter++);
}







//======================Управление потоком (блоками и переходами)===========================

// Создание и возврат ссылки на новый блок
BasicBlock* create_new_block(CFGBuilderContext* ctx) {

    if (ctx->cfg->num_blocks >= MAX_BLOCKS) return NULL;

    BasicBlock* block = &ctx->cfg->blocks[ctx->cfg->num_blocks++];

    snprintf(block->id, sizeof(block->id), "BB_%d", ctx->block_counter++);

    block->num_instructions = 0;

    block->num_successors = 0;

    return block;
}

//Добавляет target_id в successors[block]
void add_successor(BasicBlock* block, const char* target_id);

//Генерирует IR_JUMP в текущий блок.
void emit_jump(CFGBuilderContext* ctx, const char* target);

//Генерирует IR_COND_BR
void emit_cond_br(CFGBuilderContext* ctx, Operand cond, const char* true_target, const char* false_target);


//=====================Вспомогательные функции для выражений============================

//Создаёт OPERAND_VAR
Operand make_var_operand(const char* name, Type* type);


//Создаёт OPERAND_CONST  для чисел
Operand make_const_operand_int(int64_t val);

//Для true/false
Operand make_const_operand_bool(bool val);


//Для строковых литералов.
Operand make_const_operand_string(const char* str);


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
        // Левый операнд должен быть идентификатором
        if (strcmp(ts_node_type(left), "identifier") != 0) {
            fprintf(stderr, "Ошибка: левый операнд присваивания должен быть идентификатором.\n");
            // Заглушка: возвращаем int
            return make_int_type();
        }

        char var_name[64];
        get_node_text(left, ctx->source_code, var_name, sizeof(var_name));

        // Обрабатываем правый операнд
        char right_temp[64];
        generate_temp_name(ctx, right_temp, sizeof(right_temp));
        Type* right_type = visit_expr(ctx, right, right_temp);

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
        assign.data.assign.value.kind = OPERAND_VAR;
        assign.data.assign.value.data.var.name = strdup(right_temp);
        assign.data.assign.value.data.var.type = right_type;
        emit_instruction(ctx, assign);

        // Результат присваивания — значение справа (как в C)
        strcpy(result_var, right_temp);
        return right_type;
    }

    // === Все остальные операторы: вычисляют новое значение ===

    // Обрабатываем левый и правый операнды
    char left_temp[64], right_temp[64];
    generate_temp_name(ctx, left_temp, sizeof(left_temp));
    generate_temp_name(ctx, right_temp, sizeof(right_temp));

    Type* left_type = visit_expr(ctx, left, left_temp);
    Type* right_type = visit_expr(ctx, right, right_temp);

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
    generate_temp_name(ctx, operand_temp, sizeof(operand_temp));
    Type* operand_type = visit_expr(ctx, operand_node, operand_temp);

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
    unary.data.unary.operand.kind = OPERAND_VAR;
    unary.data.unary.operand.data.var.name = strdup(operand_temp);
    unary.data.unary.operand.data.var.type = operand_type;

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
                generate_temp_name(ctx, arg_temp, sizeof(arg_temp));
                Type* arg_type = visit_expr(ctx, arg_expr, arg_temp);

                args[num_args].kind = OPERAND_VAR;
                args[num_args].data.var.name = strdup(arg_temp);
                args[num_args].data.var.type = arg_type;
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
    generate_temp_name(ctx, array_name, sizeof(array_name));
    Type* array_type = visit_expr(ctx, array_expr, array_name);

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
    generate_temp_name(ctx, start_index, sizeof(start_index));
    Type* start_type = visit_expr(ctx, start_expr, start_index);

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
        generate_temp_name(ctx, end_index, sizeof(end_index));
        Type* end_type = visit_expr(ctx, end_expr, end_index);

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
        fprintf(stderr, "Ошибка: неизвестная переменная '%s'.\n", name);

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
    const char* node_type = ts_node_type(node);
    char literal_text[256];
    get_node_text(node, ctx->source_code, literal_text, sizeof(literal_text));

    // === Целочисленные литералы ===
    if (strcmp(node_type, "dec") == 0 ||
        strcmp(node_type, "hex") == 0 ||
        strcmp(node_type, "bits") == 0 ||
        strcmp(node_type, "char") == 0) {

        // Преобразуем в число
        int64_t value = 0;
        if (strcmp(node_type, "dec") == 0) {
            value = strtoll(literal_text, NULL, 10);
        }
        else if (strcmp(node_type, "hex") == 0) {
            // Убираем 0x/0X
            const char* num_start = literal_text;
            if (strncmp(literal_text, "0x", 2) == 0 || strncmp(literal_text, "0X", 2) == 0) {
                num_start += 2;
            }
            value = strtoll(num_start, NULL, 16);
        }
        else if (strcmp(node_type, "bits") == 0) {
            // Убираем 0b/0B
            const char* num_start = literal_text;
            if (strncmp(literal_text, "0b", 2) == 0 || strncmp(literal_text, "0B", 2) == 0) {
                num_start += 2;
            }
            value = strtoll(num_start, NULL, 2);
        }
        else if (strcmp(node_type, "char") == 0) {
            // 'c' → извлекаем символ между кавычками
            if (strlen(literal_text) >= 3) {
                value = (unsigned char)literal_text[1];
            }
        }

        // Генерируем временную переменную и IR_ASSIGN с константой
        generate_temp_name(ctx, result_var, 64);
        IRInstruction assign = {0};
        assign.opcode = IR_ASSIGN;
        strcpy(assign.data.assign.target, result_var);
        assign.data.assign.value = make_const_operand_int(value);
        emit_instruction(ctx, assign);

        return make_int_type();
    }

    // === Булевы литералы ===
    else if (strcmp(node_type, "bool") == 0) {
        bool value = (strcmp(literal_text, "true") == 0);
        generate_temp_name(ctx, result_var, 64);
        IRInstruction assign = {0};
        assign.opcode = IR_ASSIGN;
        strcpy(assign.data.assign.target, result_var);
        assign.data.assign.value = make_const_operand_bool(value);
        emit_instruction(ctx, assign);
        return make_bool_type();
    }

    // === Строковые литералы ===
    else if (strcmp(node_type, "str") == 0) {
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

        generate_temp_name(ctx, result_var, 64);
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
        fprintf(stderr, "Критическая ошибка: неизвестный литерал '%s' (тип: %s).\n");
        exit(1);
    }
}

//Главный диспетчер выражений — вызывает нужный обработчик по типу
Type* visit_expr(CFGBuilderContext* ctx, const TSNode node, char* result_var) {
    const char* node_type = ts_node_type(node);

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
    else {
        // Все остальные узлы — литералы
        return visit_literal_expr(ctx, node, result_var);
    }
}

//============================Обработка операторов (statements)==========================

void visit_if_statement(CFGBuilderContext* ctx, TSNode node) {
    // Структура: if <expr> then <stmt> [else <stmt>] end

    // 1. Обрабатываем условие
    char cond_var[64];
    generate_temp_name(ctx, cond_var, sizeof(cond_var));

    // Условие — это expr (обычно на позиции 1)
    TSNode cond_expr = ts_node_child_by_field_name(node, "condition", 9);
    if (ts_node_is_null(cond_expr)) {
        // fallback: берем первый expr после 'if'
        cond_expr = ts_node_child(node, 1);
    }

    Type* cond_type = visit_expr(ctx, cond_expr, cond_var);

    // Проверка: условие должно быть bool
    if (cond_type->kind != TYPE_BOOL) {
        fprintf(stderr, "Критическая ошибка: условие должно быть bool. Компиляция прервана.\n");
        exit(1);
    }

    // 2. Создаём блоки
    BasicBlock* then_block = create_new_block(ctx);
    BasicBlock* else_block = create_new_block(ctx);
    BasicBlock* merge_block = create_new_block(ctx);

    if (!then_block || !else_block || !merge_block) {
        return; // ошибка выделения
    }

    // 3. Генерируем условный переход из текущего блока
    Operand cond_op = {0};
    cond_op.kind = OPERAND_VAR;
    cond_op.data.var.name = strdup(cond_var); // или копия в стеке
    cond_op.data.var.type = cond_type;

    IRInstruction cond_br = {0};
    cond_br.opcode = IR_COND_BR;
    cond_br.data.cond_br.condition = cond_op;
    strcpy(cond_br.data.cond_br.true_target, then_block->id);
    strcpy(cond_br.data.cond_br.false_target, else_block->id);

    emit_instruction(ctx, cond_br);

    // 4. Обрабатываем тело then
    BasicBlock* saved_block = ctx->current_block;
    ctx->current_block = then_block;

    TSNode consequence = ts_node_child_by_field_name(node, "consequence", 11);
    if (!ts_node_is_null(consequence)) {
        visit_statement(ctx, consequence);
    }

    // Безусловный переход в merge
    IRInstruction jump_then = {0};
    jump_then.opcode = IR_JUMP;
    strcpy(jump_then.data.jump.target, merge_block->id);
    emit_instruction(ctx, jump_then);

    // 5. Обрабатываем тело else (если есть)
    ctx->current_block = else_block;

    TSNode alternative = ts_node_child_by_field_name(node, "alternative", 11);
    if (!ts_node_is_null(alternative)) {
        visit_statement(ctx, alternative);
    }

    // Безусловный переход в merge
    IRInstruction jump_else = {0};
    jump_else.opcode = IR_JUMP;
    strcpy(jump_else.data.jump.target, merge_block->id);
    emit_instruction(ctx, jump_else);

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
    char cond_var[64];
    generate_temp_name(ctx, cond_var, sizeof(cond_var));

    TSNode cond_expr = ts_node_child_by_field_name(node, "condition", 9);
    if (ts_node_is_null(cond_expr)) {
        cond_expr = ts_node_child(node, 1); // fallback
    }

    Type* cond_type = visit_expr(ctx, cond_expr, cond_var);

    // Проверка: условие должно быть bool
    if (cond_type->kind != TYPE_BOOL) {
        fprintf(stderr, "Критическая ошибка: условие должно быть bool. Компиляция прервана.\n");
        exit(1);
    }

    // 3. Создаём блоки
    BasicBlock* header_block = create_new_block(ctx);  // проверка условия
    BasicBlock* body_block = create_new_block(ctx);    // тело цикла
    BasicBlock* exit_block = create_new_block(ctx);    // выход

    if (!header_block || !body_block || !exit_block) {
        return;
    }

    // 4. Безусловный переход в header из текущего блока
    IRInstruction jump_to_header = {0};
    jump_to_header.opcode = IR_JUMP;
    strcpy(jump_to_header.data.jump.target, header_block->id);
    emit_instruction(ctx, jump_to_header);

    // 5. Header: условный переход
    ctx->current_block = header_block;

    Operand cond_op = {0};
    cond_op.kind = OPERAND_VAR;
    cond_op.data.var.name = strdup(cond_var);
    cond_op.data.var.type = cond_type;

    IRInstruction cond_br = {0};
    cond_br.opcode = IR_COND_BR;
    cond_br.data.cond_br.condition = cond_op;

    if (is_until) {
        // until: повторять, пока условие ЛОЖНО → выход при true
        strcpy(cond_br.data.cond_br.true_target, exit_block->id);
        strcpy(cond_br.data.cond_br.false_target, body_block->id);
    } else {
        // while: повторять, пока условие ИСТИННО → выход при false
        strcpy(cond_br.data.cond_br.true_target, body_block->id);
        strcpy(cond_br.data.cond_br.false_target, exit_block->id);
    }

    emit_instruction(ctx, cond_br);

    // 6. Body: обрабатываем все statement'ы до 'end'
    ctx->current_block = body_block;

    // Сохраняем текущую глубину цикла для break
    int saved_loop_depth = ctx->loop_depth;
    push_loop_exit(ctx, exit_block->id); // добавляем exit в стек

    // Обходим тело: все дети после условия до 'end'

    uint32_t child_count = ts_node_child_count(node);

    // Дети: [0]=keyword, [1]=condition, [2...]=statement или 'end'
    for (uint32_t i = 2; i < child_count; i++) {
        TSNode stmt = ts_node_child(node, i);
        if (strcmp(ts_node_type(stmt), "end") == 0) {
            break;
        }
        visit_statement(ctx, stmt);
    }

    // Восстанавливаем глубину
    pop_loop_exit(ctx);
    ctx->loop_depth = saved_loop_depth;

    // Безусловный переход обратно в header
    IRInstruction jump_back = {0};
    jump_back.opcode = IR_JUMP;
    strcpy(jump_back.data.jump.target, header_block->id);
    emit_instruction(ctx, jump_back);

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
    IRInstruction jump_to_body = {0};
    jump_to_body.opcode = IR_JUMP;
    strcpy(jump_to_body.data.jump.target, body_block->id);
    emit_instruction(ctx, jump_to_body);

    // 6. Обрабатываем тело
    ctx->current_block = body_block;

    // Добавляем exit в стек для break
    int saved_loop_depth = ctx->loop_depth;
    push_loop_exit(ctx, exit_block->id);

    visit_statement(ctx, body_stmt);

    pop_loop_exit(ctx);
    ctx->loop_depth = saved_loop_depth;

    // 7. Переход к заголовку (проверке условия)
    IRInstruction jump_to_header = {0};
    jump_to_header.opcode = IR_JUMP;
    strcpy(jump_to_header.data.jump.target, header_block->id);
    emit_instruction(ctx, jump_to_header);

    // 8. Header: вычисляем условие
    ctx->current_block = header_block;

    char cond_var[64];
    generate_temp_name(ctx, cond_var, sizeof(cond_var));
    Type* cond_type = visit_expr(ctx, cond_expr, cond_var);

    // Проверка: только bool
    if (cond_type->kind != TYPE_BOOL) {
        fprintf(stderr, "Ошибка: условие repeat-цикла должно быть типа 'bool'.\n");
        exit(1);
    }

    Operand cond_op = {0};
    cond_op.kind = OPERAND_VAR;
    cond_op.data.var.name = strdup(cond_var);
    cond_op.data.var.type = cond_type;

    IRInstruction cond_br = {0};
    cond_br.opcode = IR_COND_BR;
    cond_br.data.cond_br.condition = cond_op;

    if (is_until) {
        // repeat ... until cond; → выход при true
        strcpy(cond_br.data.cond_br.true_target, exit_block->id);
        strcpy(cond_br.data.cond_br.false_target, body_block->id);
    } else {
        // repeat ... while cond; → выход при false
        strcpy(cond_br.data.cond_br.true_target, body_block->id);
        strcpy(cond_br.data.cond_br.false_target, exit_block->id);
    }

    emit_instruction(ctx, cond_br);

    // 9. Выход из цикла
    ctx->current_block = exit_block;
}

// Генерирует IR_JUMP к текущему loop_exit (требует стека циклов).
void visit_break_statement(const CFGBuilderContext* ctx, TSNode node) {
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
    IRInstruction jump = {0};
    jump.opcode = IR_JUMP;
    strcpy(jump.data.jump.target, exit_block_id);
    emit_instruction(ctx, jump);
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
    generate_temp_name(ctx, result_var, sizeof(result_var));
    Type* expr_type = visit_expr(ctx, expr_node, result_var);

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
    Operand ret_value = {0};
    ret_value.kind = OPERAND_VAR;
    ret_value.data.var.name = strdup(result_var);
    ret_value.data.var.type = expr_type;

    IRInstruction ret = {0};
    ret.opcode = IR_RET;
    ret.data.ret.has_value = true;
    ret.data.ret.value = ret_value;
    emit_instruction(ctx, ret);
}

//Обрабатывает expr; — вызывает visit_expr с игнорированием результата или сохранением в _.
void visit_expression_statement(CFGBuilderContext* ctx, TSNode node) {
    // expression_statement: expr ';'

    // Выражение — первый ребёнок (до ';')
    const TSNode expr = ts_node_child(node, 0);
    if (ts_node_is_null(expr)) {
        return; // пустой оператор
    }

    // Даже если результат не используется, выражение может иметь побочные эффекты
    // (например, вызов функции, присваивание)
    char dummy_result[64];
    generate_temp_name(ctx, dummy_result, sizeof(dummy_result));
    visit_expr(ctx, expr, dummy_result);
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


//=================================== Типы и память=========================================

// Вспомогательная функция для преобразования имени типа в TypeKind
static TypeKind builtin_name_to_kind(const char* name) {

    if (strcmp(name, "bool") == 0) return TYPE_BOOL;

    if (strcmp(name, "string") == 0) return TYPE_STRING;

    // Все числовые типы → TYPE_INT
    if (strcmp(name, "int") == 0 ||
        strcmp(name, "byte") == 0 ||
        strcmp(name, "char") == 0 ||
        strcmp(name, "uint") == 0 ||
        strcmp(name, "long") == 0 ||
        strcmp(name, "ulong") == 0) {
        return TYPE_INT;
        }

    // Если неизвестный тип — считаем int
    return TYPE_INT;
}

//Конвертации типа из AST → Type*
Type* ast_type_node_to_ir_type(const TSNode type_node, const char* source_code) {
    const char* node_type = ts_node_type(type_node);

    // Случай 1: это встроенный тип
    if (strcmp(node_type, "builtin_type") == 0) {
        char name[64];
        get_node_text(type_node, source_code, name, sizeof(name));
        Type* t = malloc(sizeof(Type));
        if (!t) return NULL;
        t->kind = builtin_name_to_kind(name);
        return t;
    }

    // Случай 2: это массив — структура: (type_ref 'array' '[' dec ']')
    const uint32_t child_count = ts_node_child_count(type_node);

    if (child_count >= 4) {
        const TSNode second = ts_node_child(type_node, 1);

        if (!ts_node_is_named(second)) { // 'array' — терминал

            char token[16];

            get_node_text(second, source_code, token, sizeof(token));

            if (strcmp(token, "array") == 0) {

                Type* t = malloc(sizeof(Type));
                if (!t) return NULL;

                t->kind = TYPE_ARRAY;

                const TSNode elem_type_node = ts_node_child(type_node, 0);

                Type* elem_type = ast_type_node_to_ir_type(elem_type_node, source_code);

                if (!elem_type) {
                    free(t);
                    return NULL;
                }

                t->data.array_info.element_type = elem_type;

                uint32_t size = 0;

                for (uint32_t i = 0; i < child_count; i++) {
                    const TSNode child = ts_node_child(type_node, i);

                    if (strcmp(ts_node_type(child), "dec") == 0) {

                        char size_str[32];

                        get_node_text(child, source_code, size_str, sizeof(size_str));

                        size = (uint32_t)strtoul(size_str, NULL, 10);

                        break;
                    }
                }

                t->data.array_info.size = size;

                return t;
            }
        }
    }
}

// =================================Контекст циклов (для break)========

// При входе в цикл.
void push_loop_exit(CFGBuilderContext* ctx, const char* exit_id);

// При выходе из цикла.
void pop_loop_exit(CFGBuilderContext* ctx);

//Для break
const char* current_loop_exit(CFGBuilderContext* ctx);


// Обрабатывает тело функции (все statement'ы внутри source_item)
void visit_source_item(CFGBuilderContext* ctx, const TSNode node) {

    const uint32_t child_count = ts_node_child_count(node);

    // Начинаем с индекса 2:
    //   0 = 'def'
    //   1 = signature
    //   2 ... = statement или 'end'

    for (uint32_t i = 2; i < child_count; i++) {

        const TSNode stmt = ts_node_child(node, i);

        const char* stmt_type = ts_node_type(stmt);

        // Останавливаемся на 'end'
        if (strcmp(stmt_type, "end") == 0) {
            break;
        }

        // Обрабатываем statement
        visit_statement(ctx, stmt);
    }
}


CFG* cfg_build_from_ast(FunctionInfo* func_info, const char* source_code, const TSNode root_node) {

    // Создание CFG
    CFG* cfg = calloc(1, sizeof(CFG));

    if (!cfg) return NULL;

    CFGBuilderContext ctx = {0};

    ctx.cfg = cfg;

    ctx.source_code = source_code;

    ctx.current_function = func_info;

    ctx.temp_counter = 0;

    ctx.block_counter = 0;

    // Инициализируем локальные переменные
    symbol_table_init(&ctx.local_vars);

    // Копируем параметры в локальную область
    for (int i = 0; i < func_info->params.count; i++) {
        Symbol* param = &func_info->params.symbols[i];
        symbol_table_add(&ctx.local_vars, param->name, param->type);
    }

    // Создаём стартовый блок
    ctx.current_block = create_new_block(&ctx);

    if (!ctx.current_block) {
        free(cfg);
        return NULL;
    }

    strcpy(ctx.cfg->entry_block_id, ctx.current_block->id);

    ctx.loop_depth = 0;

    visit_source_item(&ctx, root_node);

    return cfg;
}
























