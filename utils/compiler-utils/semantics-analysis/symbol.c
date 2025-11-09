#include <string.h>
#include <stdbool.h>

#include "symbol.h"
#include "types.h"

void symbol_table_init(SymbolTable* table) {
    if (!table) return;
    table->count = 0;
}

bool symbol_table_add(SymbolTable* table, const char* name, Type* type) {
    if (!table || !name) return false;
    if (table->count >= 64) return false; // переполнение

    Symbol* sym = &table->symbols[table->count];

    // Копируем имя (макс. 63 символа + \0)
    strncpy(sym->name, name, 63);
    sym->name[63] = '\0';

    // Сохраняем указатель на тип (владение памятью — на вызывающем)
    sym->type = type;

    table->count++;
    return true;
}

Symbol* symbol_table_lookup(SymbolTable* table, const char* name) {
    if (!table || !name) return NULL;
    for (int i = 0; i < table->count; i++) {
        if (strcmp(table->symbols[i].name, name) == 0) {
            return &table->symbols[i];
        }
    }
    return NULL;
}

// Опционально: освобождение памяти под типы
void free_symbol_table(SymbolTable* table) {
    if (!table) return;
    for (int i = 0; i < table->count; i++) {
        // Освобождаем Type*, но не имя (оно в стеке)
        free_type(table->symbols[i].type);
    }
    table->count = 0;
}




