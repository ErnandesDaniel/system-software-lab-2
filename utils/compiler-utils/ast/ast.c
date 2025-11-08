
#include <string.h>
#include "ast.h"

// Копирует текст узла в буфер. Не добавляет экранирование — возвращает "как есть".
void get_node_text(const TSNode node, const char* source_code, char* buffer, const size_t buffer_size) {

    if (buffer_size == 0) return;

    const uint32_t start = ts_node_start_byte(node);

    const uint32_t end = ts_node_end_byte(node);

    uint32_t len = end - start;

    if (len >= buffer_size) {
        len = buffer_size - 1; // оставляем место для '\0'
    }

    memcpy(buffer, source_code + start, len);

    buffer[len] = '\0';
}







