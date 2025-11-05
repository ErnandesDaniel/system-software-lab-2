#ifndef MERMAID_UTILS_H
#define MERMAID_UTILS_H

#include "../../lib/tree-sitter/lib/include/tree_sitter/api.h"

// Function to append to diagram string
void append_to_diagram(char** diagram, const char* addition);

// Recursive function to generate Mermaid node
void generate_mermaid_node(TSNode node, const char* source, char** diagram, int* id_counter, const char* parent_id);

// Recursive function to print parse errors
void print_parse_errors(TSNode node, const char* source, int depth);

// Function to generate Mermaid diagram
char* generate_mermaid(TSNode node, const char* source);

#endif // MERMAID_UTILS_H