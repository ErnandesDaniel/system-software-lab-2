

//======================Управление потоком (блоками и переходами)===========================

#include <stdio.h>

#include "types.h"
#include "block_manage.h"

#include <string.h>
// Создание и возврат ссылки на новый блок
BasicBlock* create_new_block(CFGBuilderContext* ctx) {
    if (ctx->cfg->num_blocks >= MAX_BLOCKS) {
        return NULL;
    }

    BasicBlock* block = &ctx->cfg->blocks[ctx->cfg->num_blocks++];

    // Обнуляем всю структуру блока (включая массивы instructions и successors)
    memset(block, 0, sizeof(BasicBlock));

    // Теперь безопасно устанавливаем ID
    snprintf(block->id, sizeof(block->id), "BB_%d", ctx->block_counter++);

    // num_instructions и num_successors уже 0 благодаря memset,
    // но можно оставить для ясности (хотя это избыточно)
    // block->num_instructions = 0;
    // block->num_successors = 0;

    return block;
}



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

// Добавляет target_id в successors[block]
void add_successor(BasicBlock* block, const char* target_id) {
    if (!block || !target_id) return;
    if (block->num_successors >= MAX_SUCCESSORS) return; // защита от переполнения

    // Проверяем, нет ли уже такого преемника (опционально)
    for (size_t i = 0; i < block->num_successors; i++) {
        if (strcmp(block->successors[i], target_id) == 0) {
            return; // уже есть
        }
    }

    strcpy(block->successors[block->num_successors], target_id);
    block->num_successors++;
}

// Генерирует IR_JUMP в текущий блок
void emit_jump(CFGBuilderContext* ctx, const char* target) {
    if (!ctx || !ctx->current_block || !target) return;

    IRInstruction jump = {0};
    jump.opcode = IR_JUMP;
    strcpy(jump.data.jump.target, target);
    emit_instruction(ctx, jump);

    // Опционально: добавить target как преемника текущего блока
    add_successor(ctx->current_block, target);
}

//Генерирует IR_COND_BR
void emit_cond_br(CFGBuilderContext* ctx, Operand cond, const char* true_target, const char* false_target) {
    if (!ctx || !ctx->current_block || !true_target || !false_target) return;

    IRInstruction cond_br = {0};
    cond_br.opcode = IR_COND_BR;
    cond_br.data.cond_br.condition = cond;
    strcpy(cond_br.data.cond_br.true_target, true_target);
    strcpy(cond_br.data.cond_br.false_target, false_target);
    emit_instruction(ctx, cond_br);

    // Добавляем оба блока как преемников
    add_successor(ctx->current_block, true_target);
    add_successor(ctx->current_block, false_target);
}












