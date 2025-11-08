#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

typedef enum {
    TYPE_BOOL,
    TYPE_INT,
    TYPE_STRING,
    TYPE_VOID,
    TYPE_ARRAY,
} TypeKind;

typedef struct Type {
    TypeKind kind;
    union {
        struct {
            struct Type* element_type;
            uint32_t size;
        } array_info;
    } data;
} Type;


// Фабрики типов
Type* make_bool_type(void);
Type* make_int_type(void);
Type* make_string_type(void);
Type* make_void_type(void);
Type* make_array_type(Type* element_type, uint32_t size);


#endif