#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "../src/tree_sitter/parser.h"

#include "cfg.h"
#include "block_manage.h"
#include "statements.h"

TSLanguage *tree_sitter_mylang(); // Объявляем функцию из parser.c

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