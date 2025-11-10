#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "mermaid.h"

// Вспомогательная функция для форматирования операнда
void format_operand(const Operand* op, char* buffer, size_t size) {
    if (!op || !buffer || size == 0) {
        strncpy(buffer, "?", size - 1);
        buffer[size - 1] = '\0';
        return;
    }

    if (op->kind == OPERAND_VAR) {
        snprintf(buffer, size, "%s", op->data.var.name);
    } else if (op->kind == OPERAND_CONST) {
        if (op->data.const_val.type->kind == TYPE_BOOL) {
            snprintf(buffer, size, "%s", op->data.const_val.value.integer ? "true" : "false");
        } else if (op->data.const_val.type->kind == TYPE_STRING) {
            snprintf(buffer, size, "\"%s\"", op->data.const_val.value.string);
        } else {
            snprintf(buffer, size, "%d", (int)op->data.const_val.value.integer);
        }
    } else {
        snprintf(buffer, size, "?");
    }
}

// Преобразует IRInstruction в строку для отображения
void format_ir_instruction(const IRInstruction* inst, char* buffer, size_t size) {
    if (!inst || !buffer || size == 0) {
        strncpy(buffer, "<invalid>", size - 1);
        buffer[size - 1] = '\0';
        return;
    }

    switch (inst->opcode) {
        case IR_ADD: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = %s + %s", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_SUB: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = %s - %s", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_MUL: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = %s * %s", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_DIV: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = %s / %s", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_EQ: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = (%s == %s)", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_NE: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = (%s != %s)", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_LT: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = (%s < %s)", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_LE: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = (%s <= %s)", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_GT: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = (%s > %s)", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_GE: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = (%s >= %s)", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_AND: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = %s && %s", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_OR: {
            char op1[64], op2[64];
            format_operand(&inst->data.compute.operands[0], op1, sizeof(op1));
            format_operand(&inst->data.compute.operands[1], op2, sizeof(op2));
            snprintf(buffer, size, "%s = %s || %s", inst->data.compute.result, op1, op2);
            break;
        }
        case IR_NOT: {
            char op[64];
            format_operand(&inst->data.unary.operand, op, sizeof(op));
            snprintf(buffer, size, "%s = !%s", inst->data.unary.result, op);
            break;
        }
        case IR_NEG: {
            char op[64];
            format_operand(&inst->data.unary.operand, op, sizeof(op));
            snprintf(buffer, size, "%s = -%s", inst->data.unary.result, op);
            break;
        }
        case IR_POS: {
            char op[64];
            format_operand(&inst->data.unary.operand, op, sizeof(op));
            snprintf(buffer, size, "%s = +%s", inst->data.unary.result, op);
            break;
        }
        case IR_BIT_NOT: {
            char op[64];
            format_operand(&inst->data.unary.operand, op, sizeof(op));
            snprintf(buffer, size, "%s = ~%s", inst->data.unary.result, op);
            break;
        }
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
            char args[256] = {0};
            char* ptr = args;
            size_t remaining = sizeof(args);
            for (int i = 0; i < inst->data.call.num_args; i++) {
                char arg[64];
                format_operand(&inst->data.call.args[i], arg, sizeof(arg));
                int written = snprintf(ptr, remaining, "%s%s", arg, (i < inst->data.call.num_args - 1) ? ", " : "");
                if (written < 0 || (size_t)written >= remaining) break;
                ptr += written;
                remaining -= written;
            }
            if (inst->data.call.result[0]) {
                snprintf(buffer, size, "%s = call %s(%s)",
                         inst->data.call.result,
                         inst->data.call.func_name,
                         args);
            } else {
                snprintf(buffer, size, "call %s(%s)",
                         inst->data.call.func_name,
                         args);
            }
            break;
        }
        case IR_JUMP: {
            snprintf(buffer, size, "goto %s", inst->data.jump.target);
            break;
        }
        case IR_COND_BR: {
            char cond[64];
            format_operand(&inst->data.cond_br.condition, cond, sizeof(cond));
            snprintf(buffer, size, "if %s goto %s else %s",
                     cond,
                     inst->data.cond_br.true_target,
                     inst->data.cond_br.false_target);
            break;
        }
        case IR_RET: {
            if (inst->data.ret.has_value) {
                char val[64];
                format_operand(&inst->data.ret.value, val, sizeof(val));
                snprintf(buffer, size, "return %s", val);
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
