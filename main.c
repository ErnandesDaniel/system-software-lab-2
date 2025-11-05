#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/cJSON/cJSON.h"
#include "lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "src/tree_sitter/parser.h"

// Подключаем твою грамматику
TSLanguage *tree_sitter_mylang(); // Объявляем функцию из parser.c

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

// Вспомогательная функция: копирует текст и удаляет \r и \n
char* clean_text(const char* src, size_t len) {
    if (len == 0) return NULL;

    char* cleaned = malloc(len + 1);
    if (!cleaned) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        if (c != '\r' && c != '\n') {
            cleaned[j++] = c;
        }
    }
    cleaned[j] = '\0';
    return cleaned;
}

// Функция для рекурсивного преобразования узла в JSON
cJSON* node_to_json(TSNode node, const char* source) {
    cJSON* obj = cJSON_CreateObject();

    const char* type = ts_node_type(node);
    uint32_t start_byte = ts_node_start_byte(node);
    uint32_t end_byte = ts_node_end_byte(node);

    cJSON_AddStringToObject(obj, "type", type);

    // Добавляем очищенный текст узла (без \r и \n)
    if (end_byte > start_byte) {
        size_t text_len = end_byte - start_byte;
        char* cleaned = clean_text(source + start_byte, text_len);
        if (cleaned) {
            cJSON_AddStringToObject(obj, "text", cleaned);
            free(cleaned);
        }
    }

    // Обрабатываем дочерние узлы
    uint32_t child_count = ts_node_child_count(node);
    if (child_count > 0) {
        cJSON* children = cJSON_CreateArray();
        for (uint32_t i = 0; i < child_count; i++) {
            TSNode child = ts_node_child(node, i);
            cJSON_AddItemToArray(children, node_to_json(child, source));
        }
        cJSON_AddItemToObject(obj, "children", children);
    }

    return obj;
}

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

    // Добавляем узел
    char node_line[256];
    sprintf(node_line, "%s[\"%s\"]\n", id_str, type);
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

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_json> <output_md>\n", argv[0]);
        return 1;
    }

    long file_size;
    char* content = read_file(argv[1], &file_size);
    if (!content) {
        perror("The input file could not be read");
        return 1;
    }

    // Инициализация парсера
    TSParser *parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_mylang());

    TSTree *tree = ts_parser_parse_string(parser, NULL, content, file_size);
    TSNode root_node = ts_tree_root_node(tree);

    // Преобразуем дерево в JSON
    cJSON *ast_json = node_to_json(root_node, content);

    // Основной JSON-объект
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "language", "mylang");
    cJSON_AddNumberToObject(root, "text_length", (double)file_size);
    cJSON_AddItemToObject(root, "ast", ast_json);

    // Сериализуем в строку
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json_str) {
        fprintf(stderr, "JSON generation error\n");
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(content);
        return 1;
    }

    // Записываем JSON в выходной файл
    FILE *out_json = fopen(argv[2], "w");
    if (!out_json) {
        perror("Failed to create JSON output file");
        free(json_str);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(content);
        return 1;
    }
    fputs(json_str, out_json);
    fclose(out_json);
    free(json_str);

    // Генерируем Mermaid диаграмму
    char *mermaid_str = generate_mermaid(root_node, content);

    if (!mermaid_str) {
        fprintf(stderr, "Mermaid generation error\n");
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(content);
        return 1;
    }

    // Создаем MD файл с диаграммой
    FILE *out_md = fopen(argv[3], "w");
    if (!out_md) {
        perror("Failed to create MD output file");
        free(mermaid_str);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(content);
        return 1;
    }

    fputs(mermaid_str, out_md);

    fclose(out_md);
    free(mermaid_str);

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    free(content);

    return 0;
}