#include <string.h>
#include <stdbool.h>
#include "functions.h"
#include "types.h"

// Определение глобальных переменных
FunctionInfo global_functions[MAX_FUNCTIONS];

int global_function_count = 0;

void init_function_registry(void) {
    global_function_count = 0;
    // Массив global_functions не нужно обнулять явно — register_function перезапишет нужные поля
}

bool register_function(const char* name, Type* ret_type) {

    if (!name) return false;

    if (global_function_count >= MAX_FUNCTIONS) return false;

    FunctionInfo* func = &global_functions[global_function_count];

    // Копируем имя (ограничено 63 символами + '\0')
    strncpy(func->name, name, 63);

    func->name[63] = '\0';

    // Устанавливаем возвращаемый тип
    // Если ret_type == NULL, считаем, что функция возвращает void
    func->return_type = ret_type ? ret_type : make_void_type();

    // Инициализируем таблицу параметров функции
    symbol_table_init(&func->params);

    global_function_count++;

    return true;
}

FunctionInfo* find_function(const char* name) {

    if (!name) return NULL;

    for (int i = 0; i < global_function_count; i++) {
        if (strcmp(global_functions[i].name, name) == 0) {
            return &global_functions[i];
        }
    }

    return NULL;
}

//Очистка FunctionInfo
void free_function_info(FunctionInfo* func) {
    if (!func) return;
    free_type(func->return_type);
    free_symbol_table(&func->params);
    // имя — массив, не требует free
}

//Очистка глобального реестра
void free_all_functions(void) {
    for (int i = 0; i < global_function_count; i++) {
        free_function_info(&global_functions[i]);
    }
    global_function_count = 0;
}

//Получить индекс функции по информации о ней
int get_function_index(const FunctionInfo* func) {
    if (!func) return -1;
    // global_functions — массив, func — указатель на один из его элементов
    ptrdiff_t index = func - global_functions;
    if (index >= 0 && index < global_function_count) {
        return (int)index;
    }
    return -1;
}





