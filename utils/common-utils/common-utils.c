#include "common-utils.h"
#include <stdlib.h>

// Простая функция для чтения всего файла в строку
char* read_file(const char* filename, long* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* buffer = malloc(*size + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    fread(buffer, 1, *size, f);
    buffer[*size] = '\0';
    fclose(f);
    return buffer;
}

// Рекурсивная функция для вывода ошибок разбора
void print_parse_errors(TSNode node, const char* source, int depth) {
    if (ts_node_is_error(node) || ts_node_has_error(node)) {
        // Выводим отступ для глубины
        for (int i = 0; i < depth; i++) fprintf(stderr, "  ");

        uint32_t start = ts_node_start_byte(node);
        uint32_t end = ts_node_end_byte(node);
        TSPoint start_point = ts_node_start_point(node);

        fprintf(stderr, "Error at line %u, column %u: ", start_point.row + 1, start_point.column + 1);

        if (ts_node_is_error(node)) {
            // Это узел ошибки
            if (end > start) {
                fprintf(stderr, "unexpected '");
                for (uint32_t i = start; i < end && i < start + 50; i++) {
                    if (source[i] == '\n') break;
                    fputc(source[i], stderr);
                }
                fprintf(stderr, "'");
            } else {
                fprintf(stderr, "unexpected end of input");
            }
        } else {
            // Узел содержит ошибки в дочерних узлах
            fprintf(stderr, "'%s' contains errors", ts_node_type(node));
        }
        fprintf(stderr, "\n");

        // Рекурсивно проверяем дочерние узлы
        uint32_t child_count = ts_node_child_count(node);
        for (uint32_t i = 0; i < child_count; i++) {
            TSNode child = ts_node_child(node, i);
            print_parse_errors(child, source, depth + 1);
        }
    }
}