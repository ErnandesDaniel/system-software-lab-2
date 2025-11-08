#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "../src/tree_sitter/parser.h"

#include "cfg-utils.h"

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

} CFGBuilderContext;



//===============================Утилиты для работы с tree setter===========================

// Копирует текст узла в буфер. Не добавляет экранирование — возвращает "как есть".
void get_node_text(const TSNode node, const char* source_code, char* buffer, const size_t buffer_size) {

    if (buffer_size == 0) return;

    const uint32_t start = ts_node_start_byte(node);

    const uint32_t end = ts_node_end_byte(node);

    uint32_t len = end - start;

    if (len >= buffer_size) {
        len = buffer_size - 1; // оставляем место для '\0'
    }

    memcpy(buffer, source_code + start, len);

    buffer[len] = '\0';
}

// Генерация имени переменной вида "t42"
void generate_temp_name(CFGBuilderContext* ctx, char* buffer, const size_t buffer_size) {

    if (buffer_size == 0) return;

    snprintf(buffer, buffer_size, "t%d", ctx->temp_counter++);
}

// Генерация имени базового блока вида "BB_42"
void generate_block_name(CFGBuilderContext* ctx, char* buffer, const size_t buffer_size) {

    if (buffer_size == 0) return;

    snprintf(buffer, buffer_size, "BB_%d", ctx->block_counter++);
}




//============================Обработка операторов (statements)==========================

//Диспетчер: вызывает нужную функцию в зависимости от типа узла (if_statement, loop_statement, и т.д.).
void visit_statement(CFGBuilderContext* ctx, TSNode node);

void visit_if_statement(CFGBuilderContext* ctx, TSNode node);

//Обрабатывает while и until (pre-test циклы).
void visit_loop_statement(CFGBuilderContext* ctx, TSNode node);

//Обрабатывает repeat... (post-test цикл).
void visit_repeat_statement(CFGBuilderContext* ctx, TSNode node);

// Генерирует IR_JUMP к текущему loop_exit (требует стека циклов).
void visit_break_statement(CFGBuilderContext* ctx, TSNode node);

//Генерирует IR_RET (с выражением или без).
void visit_return_statement(CFGBuilderContext* ctx, TSNode node);

//Обрабатывает expr; — вызывает visit_expr с игнорированием результата или сохранением в _.
void visit_expression_statement(CFGBuilderContext* ctx, TSNode node);

// Обходит{ ... } или begin ... end — просто последовательность statement.
void visit_block_statement(CFGBuilderContext* ctx, TSNode node);



//=====================Вспомогательные функции для выражений============================

//Создаёт OPERAND_VAR
Operand make_var_operand(const char* name, Type* type);


//Создаёт OPERAND_CONST  для чисел
Operand make_const_operand_int(int64_t val);

//Для true/false
Operand make_const_operand_bool(bool val);


//Для строковых литералов.
Operand make_const_operand_string(const char* str);


//Определяет тип выражения (пока можно заглушку — TYPE_INT или TYPE_BOOL).
Type* get_expr_type(TSNode expr_node, const char* source);


//=========================================Обработка выражений (expressions)=============




//Главный диспетчер выражений — вызывает нужный обработчик по типу
void visit_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);



//Обрабатывает a + b,x && y и т.д.
void visit_binary_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);


//Обрабатывает-x,!flag,~mask.
void visit_unary_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);


//Просто делегирует visit_expr внутреннему выражению.
void visit_parenthesized_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);



//Обрабатывает f(a, b)→ генерирует IR_CALL.
void visit_call_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);



//Доступ к массиву:arr[i]
void visit_slice_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);



//Копирует имя идентификатора в result_var
void visit_identifier_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);


//Преобразует литерал в константу → генерирует временную переменную с IR_ASSIGN константы.
void visit_literal_expr(CFGBuilderContext* ctx, TSNode node, char* result_var);


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

                t->data.array_info.element_type = ast_type_node_to_ir_type(elem_type_node, source_code);

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
// Нужно добавить

//Добавь в CFGBuilderContext
//BlockId loop_exit_stack[32];
//int loop_depth;


// При входе в цикл.
void push_loop_exit(CFGBuilderContext* ctx, const char* exit_id);

// При выходе из цикла.
void pop_loop_exit(CFGBuilderContext* ctx);

//Для break
const char* current_loop_exit(CFGBuilderContext* ctx);




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

// Обрабатывает определение функции: сигнатуру и тело (root_node)
void visit_source_item(CFGBuilderContext* ctx, TSNode node);


CFG* cfg_build_from_ast(const char* source_code, TSNode root_node) {

    // Создание CFG
    CFG* cfg = calloc(1, sizeof(CFG));

    if (!cfg) return NULL;

    CFGBuilderContext ctx = {0};

    ctx.cfg = cfg;

    ctx.source_code = source_code;

    ctx.temp_counter = 0;

    ctx.block_counter = 0;

    ctx.loop_depth = 0;

    ctx.current_block = create_new_block(&ctx);

    if (!ctx.current_block) {
        free(cfg);
        return NULL;
    }

    strcpy(cfg->entry_block_id, ctx.current_block->id);

    visit_source_item(&ctx, root_node);

    return cfg;
}








