


//=================================== Типы и память=========================================

#include "types.h"
#include "compiler-utils/semantics-analysis/types.h"
#include "../../../lib/tree-sitter/lib/include/tree_sitter/api.h"

#include <string.h>

#include "compiler-utils/ast/ast.h"
// Вспомогательная функция для преобразования имени типа в TypeKind
static TypeKind builtin_name_to_kind(const char* name) {

    if (strcmp(name, "bool") == 0) return TYPE_BOOL;

    if (strcmp(name, "string") == 0) return TYPE_STRING;

    // Все числовые типы → TYPE_INT
    if (strcmp(name, "int") == 0 ||
        strcmp(name, "byte") == 0 ||
        strcmp(name, "char") == 0 ||
        strcmp(name, "uint") == 0 ||
        strcmp(name, "long") == 0 ||
        strcmp(name, "ulong") == 0) {
        return TYPE_INT;
        }

    // Если неизвестный тип — считаем int
    return TYPE_INT;
}

//Конвертации типа из AST → Type*
Type* ast_type_node_to_ir_type(const TSNode type_node, const char* source_code) {
    const char* node_type = ts_node_type(type_node);

    // Случай 1: это встроенный тип
    if (strcmp(node_type, "builtin_type") == 0) {
        char name[64];
        get_node_text(type_node, source_code, name, sizeof(name));
        Type* t = malloc(sizeof(Type));
        if (!t) return NULL;
        t->kind = builtin_name_to_kind(name);
        return t;
    }

    // Случай 2: это массив — структура: (type_ref 'array' '[' dec ']')
    const uint32_t child_count = ts_node_child_count(type_node);

    if (child_count >= 4) {
        const TSNode second = ts_node_child(type_node, 1);

        if (!ts_node_is_named(second)) { // 'array' — терминал

            char token[16];

            get_node_text(second, source_code, token, sizeof(token));

            if (strcmp(token, "array") == 0) {

                Type* t = malloc(sizeof(Type));
                if (!t) return NULL;

                t->kind = TYPE_ARRAY;

                const TSNode elem_type_node = ts_node_child(type_node, 0);

                Type* elem_type = ast_type_node_to_ir_type(elem_type_node, source_code);

                if (!elem_type) {
                    free(t);
                    return NULL;
                }

                t->data.array_info.element_type = elem_type;

                uint32_t size = 0;

                for (uint32_t i = 0; i < child_count; i++) {
                    const TSNode child = ts_node_child(type_node, i);

                    if (strcmp(ts_node_type(child), "dec") == 0) {

                        char size_str[32];

                        get_node_text(child, source_code, size_str, sizeof(size_str));

                        size = (uint32_t)strtoul(size_str, NULL, 10);

                        break;
                    }
                }

                t->data.array_info.size = size;

                return t;
            }
        }
    }
    return make_int_type(); // fallback
}
