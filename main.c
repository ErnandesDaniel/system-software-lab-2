#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

// Функция для генерации Mermaid диаграммы
char* generate_mermaid(TSNode node, const char* source) {
    char* diagram = NULL;
    append_to_diagram(&diagram, "graph TD;\n");

    int id_counter = 0;
    generate_mermaid_node(node, source, &diagram, &id_counter, NULL);

    return diagram;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_mmd>\n", argv[0]);
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

    // Проверяем на ошибки разбора
    TSNode root_node = ts_tree_root_node(tree);
    if (ts_node_has_error(root_node)) {
        // Выводим конкретные ошибки
        fprintf(stderr, "Parsing errors:\n");
        print_parse_errors(root_node, content, 0);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(content);
        return 1;
    }

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
    FILE *out_md = fopen(argv[2], "w");
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