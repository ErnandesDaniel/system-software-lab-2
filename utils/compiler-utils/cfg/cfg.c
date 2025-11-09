#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "../src/tree_sitter/parser.h"

#include "cfg.h"

#include "compiler-utils/ast/ast.h"
#include "../semantics-analysis/functions.h"

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
Type* ensure_bool_expr(CFGBuilderContext* ctx, TSNode expr, char* result_var);
Type* eval_to_temp(CFGBuilderContext* ctx, TSNode expr, char* out_temp);
void visit_statements_with_break_context(CFGBuilderContext* ctx, TSNode parent, uint32_t start_idx, const char* exit_id);
void visit_source_item(CFGBuilderContext* ctx, TSNode node);

// ===============================================================






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

// Освобождает всю память, выделенную под CFG
void cfg_destroy_graph(CFG* cfg) {
    if (!cfg) return;

    // Освобождаем память, выделенную внутри инструкций (если есть)
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        BasicBlock* block = &cfg->blocks[i];
        for (size_t j = 0; j < block->num_instructions; j++) {
            IRInstruction* inst = &block->instructions[j];

            // Освобождаем динамически выделенные строки в операндах
            if (inst->opcode == IR_COND_BR) {
                if (inst->data.cond_br.condition.kind == OPERAND_VAR &&
                    inst->data.cond_br.condition.data.var.name) {
                    free(inst->data.cond_br.condition.data.var.name);
                    }
            }
            else if (inst->opcode == IR_ASSIGN) {
                if (inst->data.assign.value.kind == OPERAND_VAR &&
                    inst->data.assign.value.data.var.name) {
                    free(inst->data.assign.value.data.var.name);
                    }
                // Для констант-строк:
                else if (inst->data.assign.value.kind == OPERAND_CONST &&
                         inst->data.assign.value.data.const_val.type->kind == TYPE_STRING) {
                    free(inst->data.assign.value.data.const_val.value.string);
                         }
            }
            else if (inst->opcode == IR_CALL) {
                for (int k = 0; k < inst->data.call.num_args; k++) {
                    if (inst->data.call.args[k].kind == OPERAND_VAR &&
                        inst->data.call.args[k].data.var.name) {
                        free(inst->data.call.args[k].data.var.name);
                        }
                }
            }
            // Добавь обработку других опкодов по мере необходимости
        }
    }

    // Обнуляем структуру
    memset(cfg, 0, sizeof(CFG));
}