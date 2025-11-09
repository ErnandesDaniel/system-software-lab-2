#include <stdlib.h>
#include "types.h"

Type* make_bool_type(void) {
    Type* t = (Type*)malloc(sizeof(Type));
    if (!t) return NULL;
    t->kind = TYPE_BOOL;
    return t;
}

Type* make_int_type(void) {
    Type* t = (Type*)malloc(sizeof(Type));
    if (!t) return NULL;
    t->kind = TYPE_INT;
    return t;
}

Type* make_string_type(void) {
    Type* t = (Type*)malloc(sizeof(Type));
    if (!t) return NULL;
    t->kind = TYPE_STRING;
    return t;
}

Type* make_void_type(void) {
    Type* t = (Type*)malloc(sizeof(Type));
    if (!t) return NULL;
    t->kind = TYPE_VOID;
    return t;
}

Type* make_array_type(Type* element_type, const uint32_t size) {
    if (!element_type) return NULL;

    Type* t = (Type*)malloc(sizeof(Type));
    if (!t) return NULL;

    t->kind = TYPE_ARRAY;
    t->data.array_info.element_type = element_type;
    t->data.array_info.size = size;
    return t;
}

void free_type(Type* t) {
    if (!t) return;

    // Если это массив — сначала освободить элементный тип
    if (t->kind == TYPE_ARRAY) {
        free_type(t->data.array_info.element_type);
    }

    // Теперь освободить сам узел
    free(t);
}


// При создании:
// Type* int_t = make_int_type();
// Type* arr1 = make_array_type(int_t, 10);     // int array[10]
// Type* arr2 = make_array_type(arr1, 5);       // (int array[10]) array[5]


//При освобождении:
//free_type(arr2);
// → вызывает free_type(arr1)
//   → вызывает free_type(int_t)
//     → free(int_t)
//   → free(arr1)
// → free(arr2)

