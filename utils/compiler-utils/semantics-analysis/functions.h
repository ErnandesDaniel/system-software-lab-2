#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "symbol.h"

#define MAX_FUNCTIONS 64

typedef struct FunctionInfo {
    char name[64];
    Type* return_type;
    SymbolTable params;
} FunctionInfo;

// Глобальный реестр (массив) функций
extern FunctionInfo global_functions[MAX_FUNCTIONS];
extern int global_function_count;


// Утилиты для работы с функциями
void init_function_registry(void);

bool register_function(const char* name, Type* ret_type);

FunctionInfo* find_function(const char* name);

void free_function_info(FunctionInfo* func);

void free_all_functions(void);

int get_function_index(const FunctionInfo* func);

#endif





