#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <windows.h>

#include "lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "src/tree_sitter/parser.h"
#include "utils/common-utils/common-utils.h"
#include "utils/mermaid-utils/mermaid-utils.h"

// Подключаем твою грамматику
TSLanguage *tree_sitter_mylang(); // Объявляем функцию из parser.c


int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_mmd> <output_dir>\n", argv[0]);
        return 1;
    }

    long file_size;
    char* content = read_file(argv[1], &file_size);
    if (!content) {
        perror("The input file could not be read");
        return 1;
    }

    // Создаем директорию для файлов функций и очищаем ее
    if (_mkdir(argv[3]) != 0 && errno != EEXIST) {
        perror("Failed to create output directory");
        free(content);
        return 1;
    } else if (errno == EEXIST) {
        // Директория существует, очищаем ее
        char search_path[256];
        sprintf(search_path, "%s\\*", argv[3]);
        WIN32_FIND_DATA find_data;
        HANDLE hFind = FindFirstFile(search_path, &find_data);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(find_data.cFileName, ".") != 0 && strcmp(find_data.cFileName, "..") != 0) {
                    char file_path[256];
                    sprintf(file_path, "%s\\%s", argv[3], find_data.cFileName);
                    DeleteFile(file_path);
                }
            } while (FindNextFile(hFind, &find_data));
            FindClose(hFind);
        }
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

    // Генерируем Mermaid диаграмму для всего файла
    char *mermaid_str = generate_mermaid(root_node, content);

    if (!mermaid_str) {
        fprintf(stderr, "Mermaid generation error\n");
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(content);
        return 1;
    }

    // Создаем MD файл с диаграммой всего файла
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

    // Теперь генерируем файлы для каждой функции
    uint32_t child_count = ts_node_child_count(root_node);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(root_node, i);
        if (strcmp(ts_node_type(child), "source_item") == 0) {
            // Находим сигнатуру функции
            TSNode signature = ts_node_child_by_field_name(child, "signature", strlen("signature"));
            if (!ts_node_is_null(signature)) {
                TSNode func_name_node = ts_node_child_by_field_name(signature, "name", strlen("name"));
                if (!ts_node_is_null(func_name_node)) {
                    uint32_t start = ts_node_start_byte(func_name_node);
                    uint32_t end = ts_node_end_byte(func_name_node);
                    size_t len = end - start;
                    char* func_name = malloc(len + 1);
                    if (func_name) {
                        memcpy(func_name, content + start, len);
                        func_name[len] = '\0';

                        // Генерируем Mermaid для этой функции
                        char* func_mermaid = generate_mermaid(child, content);
                        if (func_mermaid) {
                            // Создаем файл для функции
                            char filepath[256];
                            sprintf(filepath, "%s\\%s.mmd", argv[3], func_name);
                            FILE* func_file = fopen(filepath, "w");
                            if (func_file) {
                                fputs(func_mermaid, func_file);
                                fclose(func_file);
                            } else {
                                fprintf(stderr, "Failed to create file for function %s\n", func_name);
                            }
                            free(func_mermaid);
                        }
                        free(func_name);
                    }
                }
            }
        }
    }

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    free(content);

    return 0;
}