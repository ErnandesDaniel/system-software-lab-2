#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "mermaid.h"

// Преобразует IRInstruction в строку для отображения
void format_ir_instruction(const IRInstruction* inst, char* buffer, size_t size) {
    if (!inst || !buffer || size == 0) {
        strncpy(buffer, "<invalid>", size - 1);
        buffer[size - 1] = '\0';
        return;
    }

    switch (inst->opcode) {
        case IR_ADD: snprintf(buffer, size, "t = a + b"); break;
        case IR_SUB: snprintf(buffer, size, "t = a - b"); break;
        case IR_MUL: snprintf(buffer, size, "t = a * b"); break;
        case IR_DIV: snprintf(buffer, size, "t = a / b"); break;
        case IR_EQ:  snprintf(buffer, size, "t = (a == b)"); break;
        case IR_NE:  snprintf(buffer, size, "t = (a != b)"); break;
        case IR_LT:  snprintf(buffer, size, "t = (a < b)"); break;
        case IR_LE:  snprintf(buffer, size, "t = (a <= b)"); break;
        case IR_GT:  snprintf(buffer, size, "t = (a > b)"); break;
        case IR_GE:  snprintf(buffer, size, "t = (a >= b)"); break;
        case IR_AND: snprintf(buffer, size, "t = a && b"); break;
        case IR_OR:  snprintf(buffer, size, "t = a || b"); break;
        case IR_NOT: snprintf(buffer, size, "t = !a"); break;
        case IR_NEG: snprintf(buffer, size, "t = -a"); break;
        case IR_POS: snprintf(buffer, size, "t = +a"); break;
        case IR_BIT_NOT: snprintf(buffer, size, "t = ~a"); break;
        case IR_ASSIGN: {
            if (inst->data.assign.value.kind == OPERAND_VAR) {
                snprintf(buffer, size, "%s = %s",
                         inst->data.assign.target,
                         inst->data.assign.value.data.var.name);
            } else if (inst->data.assign.value.kind == OPERAND_CONST) {
                if (inst->data.assign.value.data.const_val.type->kind == TYPE_BOOL) {
                    snprintf(buffer, size, "%s = %s",
                             inst->data.assign.target,
                             inst->data.assign.value.data.const_val.value.integer ? "true" : "false");
                } else if (inst->data.assign.value.data.const_val.type->kind == TYPE_STRING) {
                    snprintf(buffer, size, "%s = \"%s\"",
                             inst->data.assign.target,
                             inst->data.assign.value.data.const_val.value.string);
                } else {
                    snprintf(buffer, size, "%s = %d",
                             inst->data.assign.target,
                             (int)inst->data.assign.value.data.const_val.value.integer);
                }
            } else {
                snprintf(buffer, size, "%s = ?", inst->data.assign.target);
            }
            break;
        }
        case IR_CALL: {
            snprintf(buffer, size, "%s = call %s(...)",
                     inst->data.call.result[0] ? inst->data.call.result : "_",
                     inst->data.call.func_name);
            break;
        }
        case IR_JUMP: {
            snprintf(buffer, size, "goto %s", inst->data.jump.target);
            break;
        }
        case IR_COND_BR: {
            snprintf(buffer, size, "if %s goto %s else %s",
                     "cond", // можно улучшить, если хранить имя условия
                     inst->data.cond_br.true_target,
                     inst->data.cond_br.false_target);
            break;
        }
        case IR_RET: {
            if (inst->data.ret.has_value) {
                snprintf(buffer, size, "return %s", "value");
            } else {
                snprintf(buffer, size, "return");
            }
            break;
        }
        default:
            snprintf(buffer, size, "op_%d", (int)inst->opcode);
    }
}


// Генерирует Mermaid-диаграмму для CFG
char* cfg_generate_mermaid(const CFG* cfg) {
    if (!cfg) return strdup("graph TD\n    error[Invalid CFG]");

    // Грубая оценка размера
    size_t buf_size = 8192;
    char* buf = malloc(buf_size);
    if (!buf) return NULL;

    char* ptr = buf;
    size_t remaining = buf_size;
    int total_written = 0;

    // Заголовок
    total_written = snprintf(ptr, remaining, "graph TD\n");
    if (total_written < 0 || (size_t)total_written >= remaining) goto overflow;
    ptr += total_written;
    remaining -= total_written;

    // Генерация узлов с инструкциями
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        const BasicBlock* block = &cfg->blocks[i];
        char block_label[4096] = {0};
        char* label_ptr = block_label;
        size_t label_remaining = sizeof(block_label);

        // Заголовок блока
        int w = snprintf(label_ptr, label_remaining, "%s\\n", block->id);
        if (w < 0 || (size_t)w >= label_remaining) goto overflow;
        label_ptr += w;
        label_remaining -= w;

        // Инструкции
        for (size_t j = 0; j < block->num_instructions; j++) {
            char instr_str[256] = {0};
            format_ir_instruction(&block->instructions[j], instr_str, sizeof(instr_str));
            w = snprintf(label_ptr, label_remaining, "%s\\n", instr_str);
            if (w < 0 || (size_t)w >= label_remaining) break;
            label_ptr += w;
            label_remaining -= w;
        }

        // Формируем узел Mermaid
        w = snprintf(ptr, remaining, "    %s[\"%s\"]\n", block->id, block_label);
        if (w < 0 || (size_t)w >= remaining) goto overflow;
        ptr += w;
        remaining -= w;
    }

    // Рёбра (переходы)
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        const BasicBlock* block = &cfg->blocks[i];
        for (size_t j = 0; j < block->num_successors; j++) {
            int w = snprintf(ptr, remaining, "    %s --> %s\n",
                            block->id, block->successors[j]);
            if (w < 0 || (size_t)w >= remaining) goto overflow;
            ptr += w;
            remaining -= w;
        }
    }

    return buf;

overflow:
    free(buf);
    return strdup("graph TD\n    error[CFG too large to display]");
}
