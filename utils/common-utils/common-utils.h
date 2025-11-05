#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H

#include <stdio.h>
#include "../../lib/tree-sitter/lib/include/tree_sitter/api.h"

// Function to read entire file into a string
char* read_file(const char* filename, long* size);

// Recursive function to print parse errors
void print_parse_errors(TSNode node, const char* source, int depth);

#endif // COMMON_UTILS_H