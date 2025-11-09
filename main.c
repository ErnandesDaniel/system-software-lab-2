#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <windows.h>

#include "lib/tree-sitter/lib/include/tree_sitter/api.h"
#include "src/tree_sitter/parser.h"
#include "utils/common-utils/common-utils.h"
#include "utils/mermaid-utils/mermaid-utils.h"

#include "utils/compiler-utils/ast/ast.h"

#include "utils/compiler-utils/cfg/cfg.h"

#include "utils/compiler-utils/semantics-analysis/functions.h"

#include "compiler-utils/semantics-analysis/semantics-analysis.h"


// Подключаем твою грамматику
TSLanguage *tree_sitter_mylang(); // Объявляем функцию из parser.c


int main(const int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_mmd> <output_dir>\n", argv[0]);
        return 1;
    }

    long file_size;
    char* source_code = read_file(argv[1], &file_size);
    if (!source_code) {
        perror("The input file could not be read");
        return 1;
    }

    // Создаем директорию для файлов функций и очищаем ее
    if (_mkdir(argv[3]) != 0 && errno != EEXIST) {
        perror("Failed to create output directory");
        free(source_code);
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

    //Парсинг
    TSTree *tree = ts_parser_parse_string(parser, NULL, source_code, file_size);

    const TSNode root_node = ts_tree_root_node(tree);

    // Проверяем на ошибки разбора
    if (ts_node_has_error(root_node)) {
        // Выводим конкретные ошибки
        fprintf(stderr, "Parsing errors:\n");
        print_parse_errors(root_node, source_code, 0);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(source_code);
        return 1;
    }

    // Генерируем Mermaid диаграмму для всего файла
    char *mermaid_str = generate_mermaid(root_node, source_code);

    if (!mermaid_str) {
        fprintf(stderr, "Mermaid generation error\n");
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(source_code);
        return 1;
    }

    // Создаем MD файл с диаграммой всего файла
    FILE *out_md = fopen(argv[2], "w");
    if (!out_md) {
        perror("Failed to create MD output file");
        free(mermaid_str);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        free(source_code);
        return 1;
    }

    fputs(mermaid_str, out_md);

    fclose(out_md);
    free(mermaid_str);

    // 2. Семантический анализ (генерация массива данных о функциях)
    build_global_symbol_table(root_node, source_code);

    // Массив для хранения всех CFG
    CFG* function_cfgs[MAX_FUNCTIONS] = {0}; // инициализируем нулями

    // Теперь генерируем файлы для каждой функции
    const uint32_t child_count = ts_node_child_count(root_node);

    for (uint32_t i = 0; i < child_count; i++) {


        TSNode child = ts_node_child(root_node, i);

        if (strcmp(ts_node_type(child), "source_item") != 0) continue;

        // Находим сигнатуру функции
        const TSNode signature = ts_node_child_by_field_name(child, "signature", strlen("signature"));
        if (ts_node_is_null(signature)) continue;

        // Находим имя функции
        const TSNode func_name_node = ts_node_child_by_field_name(signature, "name", strlen("name"));
        if (ts_node_is_null(func_name_node)) continue;

        char func_name[64];
        get_node_text(func_name_node, source_code, func_name, sizeof(func_name));

        // Находим FunctionInfo по имени
        FunctionInfo* func_info = find_function(func_name);
        if (!func_info) continue;

        // Строим CFG для этой функции
        CFG* func_cfg = cfg_build_from_ast(func_info, source_code, child);
        if (!func_cfg) continue;

        // Получаем индекс функции
        int idx = get_function_index(func_info);
        if (idx == -1) continue;

        // Сохраняем граф в массив
        function_cfgs[idx] = func_cfg;

        if (func_cfg) {
            // Генерируем Mermaid диаграмму из CFG
            char* func_mermaid = cfg_generate_mermaid(func_cfg);


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

            cfg_destroy_graph(func_cfg);
        }
    }

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    free(source_code);

    return 0;
}