#include <string.h>
#include "../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "compiler-utils/ast/ast.h"
#include "functions.h"
#include "types.h"
#include "symbol.h"

// Вспомогательная функция: преобразует узел типа в Type*
static Type* parse_type_node(const TSNode type_node, const char* source) {

    if (ts_node_is_null(type_node)) return NULL;

    const char* type_name = ts_node_type(type_node);

    // Встроенный тип: 'int', 'bool' и т.д.
    if (strcmp(type_name, "builtin_type") == 0) {

        char name[64];

        get_node_text(type_node, source, name, sizeof(name));

        if (strcmp(name, "bool") == 0) return make_bool_type();

        if (strcmp(name, "string") == 0) return make_string_type();

        return make_int_type(); // все числовые типы → int
    }

    // Массив: type_ref 'array' '[' dec ']'
    if (strcmp(type_name, "type_ref") == 0) {

        // Проверяем, является ли это массивом
        const uint32_t child_count = ts_node_child_count(type_node);

        for (uint32_t i = 0; i < child_count; i++) {

            const TSNode child = ts_node_child(type_node, i);

            if (!ts_node_is_named(child)) {

                char token[16];

                get_node_text(child, source, token, sizeof(token));

                if (strcmp(token, "array") == 0) {
                    // Это массив
                    // Элементный тип — первый дочерний узел
                    const TSNode elem_type_node = ts_node_child(type_node, 0);
                    Type* elem_type = parse_type_node(elem_type_node, source);
                    if (!elem_type) elem_type = make_int_type();

                    // Ищем размер (dec)
                    uint32_t size = 1;

                    for (uint32_t j = 0; j < child_count; j++) {

                        const TSNode c = ts_node_child(type_node, j);

                        if (strcmp(ts_node_type(c), "dec") == 0) {

                            char size_str[32];

                            get_node_text(c, source, size_str, sizeof(size_str));

                            size = (uint32_t)strtoul(size_str, NULL, 10);

                            break;
                        }
                    }

                    return make_array_type(elem_type, size);
                }
            }
        }
        // Если не массив — рекурсивно обработать как type_ref
        // (например, вложенный массив или базовый тип)
        return parse_type_node(ts_node_child(type_node, 0), source);
    }

    return make_int_type(); // fallback
}

// Обрабатывает один параметр функции (узел "arg")
static void process_parameter(const TSNode arg_node, SymbolTable* params_table, const char* source) {

    // Имя: поле "name"
    const TSNode name_node = ts_node_child_by_field_name(arg_node, "name", 4);

    if (ts_node_is_null(name_node)) return;

    char name[64];

    get_node_text(name_node, source, name, sizeof(name));

    // Тип: поле "type" (опционально)
    const TSNode type_node = ts_node_child_by_field_name(arg_node, "type", 4);

    Type* param_type = parse_type_node(type_node, source);

    if (!param_type) param_type = make_int_type(); // по умолчанию int

    symbol_table_add(params_table, name, param_type);
}

// Обрабатывает список параметров (узел "list_arg")
static void process_parameters(TSNode params_node, SymbolTable* params_table, const char* source) {
    if (ts_node_is_null(params_node)) return;

    // list_arg: arg (',' arg)*
    const uint32_t child_count = ts_node_child_count(params_node);

    for (uint32_t i = 0; i < child_count; i++) {
        const TSNode child = ts_node_child(params_node, i);

        if (strcmp(ts_node_type(child), "arg") == 0) {

            process_parameter(child, params_table, source);

        }
    }
}

// Обрабатывает одну функцию (узел "source_item")
static void process_function(TSNode func_item, const char* source) {
    // Имя функции: поле "name" в func_signature
    const TSNode sig_node = ts_node_child_by_field_name(func_item, "signature", 9);
    if (ts_node_is_null(sig_node)) return;

    const TSNode name_node = ts_node_child_by_field_name(sig_node, "name", 4);
    if (ts_node_is_null(name_node)) return;

    char func_name[64];
    get_node_text(name_node, source, func_name, sizeof(func_name));

    // Возвращаемый тип: поле "return_type" (опционально)
    const TSNode ret_type_node = ts_node_child_by_field_name(sig_node, "return_type", 11);

    Type* ret_type = parse_type_node(ret_type_node, source);
    // Если ret_type == NULL → register_function создаст void

    // Регистрируем функцию
    if (!register_function(func_name, ret_type)) {
        // Ошибка: слишком много функций
        return;
    }

    // Находим только что добавленную функцию
    FunctionInfo* func = find_function(func_name);
    if (!func) return;

    // Обрабатываем параметры
    const TSNode params_node = ts_node_child_by_field_name(sig_node, "parameters", 10);

    process_parameters(params_node, &func->params, source);
}

// Основная функция: проход по AST и заполнение global_functions
void build_global_symbol_table(const TSNode root, const char* source_code) {

    init_function_registry();

    const uint32_t child_count = ts_node_child_count(root);

    for (uint32_t i = 0; i < child_count; i++) {

        const TSNode child = ts_node_child(root, i);

        if (strcmp(ts_node_type(child), "source_item") == 0) {

            process_function(child, source_code);

        }
    }
}