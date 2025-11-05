#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

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

    // Для идентификаторов и десятичных литералов добавляем узел с текстом
    if (strcmp(type, "identifier") == 0 || strcmp(type, "dec") == 0) {
        uint32_t start = ts_node_start_byte(node);
        uint32_t end = ts_node_end_byte(node);
        uint32_t len = end - start;
        char* text = malloc(len + 1);
        memcpy(text, source + start, len);
        text[len] = '\0';

        int text_id = (*id_counter)++;
        char text_id_str[16];
        sprintf(text_id_str, "N%d", text_id);

        char text_node_line[256];
        sprintf(text_node_line, "%s[\"%s\"]\n", text_id_str, text);
        append_to_diagram(diagram, text_node_line);

        char text_edge_line[256];
        sprintf(text_edge_line, "%s --> %s\n", id_str, text_id_str);
        append_to_diagram(diagram, text_edge_line);

        free(text);
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

// Функция для генерации Mermaid диаграммы для функции
char* generate_mermaid_for_function(TSNode func_node, const char* source) {
    char* diagram = NULL;
    append_to_diagram(&diagram, "graph TD;\n");

    int id_counter = 0;
    generate_mermaid_node(func_node, source, &diagram, &id_counter, NULL);

    return diagram;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_md> <cfg_dir>\n", argv[0]);
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

    // Генерируем Mermaid диаграмму для всего дерева
    char *mermaid_str = generate_mermaid(root_node, content);

    if (!mermaid_str) {
        fprintf(stderr, "Mermaid generation error\n");
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(content);
        return 1;
    }

    // Создаем MD файл с общей диаграммой
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

    // Создаем директорию для функций
    mkdir(argv[3]);

    // Обрабатываем дочерние узлы корневого узла
    uint32_t child_count = ts_node_child_count(root_node);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(root_node, i);
        const char* child_type = ts_node_type(child);

        if (strcmp(child_type, "source_item") == 0) {
            // Находим функцию в source_item
            uint32_t func_child_count = ts_node_child_count(child);
            for (uint32_t j = 0; j < func_child_count; j++) {
                TSNode func_child = ts_node_child(child, j);
                const char* func_child_type = ts_node_type(func_child);

                if (strcmp(func_child_type, "func_signature") == 0) {
                    // Находим имя функции
                    uint32_t sig_child_count = ts_node_child_count(func_child);
                    for (uint32_t k = 0; k < sig_child_count; k++) {
                        TSNode sig_child = ts_node_child(func_child, k);
                        const char* sig_child_type = ts_node_type(sig_child);

                        if (strcmp(sig_child_type, "identifier") == 0) {
                            // Извлекаем имя функции
                            uint32_t start = ts_node_start_byte(sig_child);
                            uint32_t end = ts_node_end_byte(sig_child);
                            uint32_t len = end - start;
                            char* func_name = malloc(len + 1);
                            memcpy(func_name, content + start, len);
                            func_name[len] = '\0';

                            // Генерируем Mermaid диаграмму для функции
                            char *func_mermaid_str = generate_mermaid_for_function(child, content);

                            if (func_mermaid_str) {
                                // Создаем файл с именем функции
                                char filename[256];
                                sprintf(filename, "%s/%s.mmd", argv[3], func_name);
                                FILE *func_out_md = fopen(filename, "w");
                                if (func_out_md) {
                                    fputs(func_mermaid_str, func_out_md);
                                    fclose(func_out_md);
                                } else {
                                    perror("Failed to create output file");
                                }
                                free(func_mermaid_str);
                            }

                            free(func_name);
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    free(content);

    return 0;
}