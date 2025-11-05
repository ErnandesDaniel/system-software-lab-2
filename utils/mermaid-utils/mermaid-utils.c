#include "mermaid-utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Вспомогательная функция для добавления строки к диаграмме
void append_to_diagram(char** diagram, const char* addition) {
    size_t current_len = *diagram ? strlen(*diagram) : 0;
    size_t addition_len = strlen(addition);
    *diagram = realloc(*diagram, current_len + addition_len + 1);
    if (!*diagram) {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }
    strcpy(*diagram + current_len, addition);
}

// Рекурсивная функция для генерации Mermaid диаграммы
void generate_mermaid_node(TSNode node, const char* source, char** diagram, int* id_counter, const char* parent_id) {
    int current_id = (*id_counter)++;
    char id_str[16];
    sprintf(id_str, "N%d", current_id);

    const char* type = ts_node_type(node);

    // Получаем текст узла для идентификаторов и литералов
    char* text = NULL;
    if (strcmp(type, "identifier") == 0 ||
        strcmp(type, "bool") == 0 ||
        strcmp(type, "str") == 0 ||
        strcmp(type, "char") == 0 ||
        strcmp(type, "hex") == 0 ||
        strcmp(type, "bits") == 0 ||
        strcmp(type, "dec") == 0) {
        uint32_t start = ts_node_start_byte(node);
        uint32_t end = ts_node_end_byte(node);
        size_t len = end - start;
        text = malloc(len + 1);
        if (text) {
            memcpy(text, source + start, len);
            text[len] = '\0';
        }
    }

    // Добавляем узел
    char node_line[256];
    if (text) {
        sprintf(node_line, "%s[\"%s: %s\"]\n", id_str, type, text);
        free(text);
    } else {
        sprintf(node_line, "%s[\"%s\"]\n", id_str, type);
    }
    append_to_diagram(diagram, node_line);

    // Соединяем с родителем
    if (parent_id) {
        char edge_line[256];
        sprintf(edge_line, "%s --> %s\n", parent_id, id_str);
        append_to_diagram(diagram, edge_line);
    }

    // Обрабатываем дочерние узлы
    uint32_t child_count = ts_node_child_count(node);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(node, i);
        generate_mermaid_node(child, source, diagram, id_counter, id_str);
    }
}

// Функция для генерации Mermaid диаграммы
char* generate_mermaid(TSNode node, const char* source) {
    char* diagram = NULL;
    append_to_diagram(&diagram, "graph TD;\n");

    int id_counter = 0;
    generate_mermaid_node(node, source, &diagram, &id_counter, NULL);

    return diagram;
}