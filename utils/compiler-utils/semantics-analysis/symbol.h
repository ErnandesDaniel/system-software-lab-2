#ifndef SYMBOL_H
#define SYMBOL_H

#include <stdbool.h>
#include "types.h"

typedef struct Symbol {
    char name[64]; // имя: "x", "counter", "result"
    Type* type; // тип: TYPE_INT, TYPE_BOOL, TYPE_ARRAY и т.д.
} Symbol;

typedef struct SymbolTable {
    Symbol symbols[64];
    int count;
} SymbolTable;

void symbol_table_init(SymbolTable* table);
bool symbol_table_add(SymbolTable* table, const char* name, Type* type);
Symbol* symbol_table_lookup(SymbolTable* table, const char* name);

#endif