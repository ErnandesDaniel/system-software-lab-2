#ifndef CFG_H
#define CFG_H

#include "../semantics-analysis/functions.h"
#include "types.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

CFG* cfg_build_from_ast(FunctionInfo* func_info, const char* source_code, TSNode root_node);

void cfg_destroy_graph(CFG* cfg);

char* cfg_generate_mermaid(const CFG* cfg);


#endif