#ifndef CFG_MERMAID_H
#define CFG_MERMAID_H

#include "cfg.h"
char* cfg_generate_mermaid(const CFG* cfg);

void format_ir_instruction(const IRInstruction* inst, char* buffer, size_t size);

#endif