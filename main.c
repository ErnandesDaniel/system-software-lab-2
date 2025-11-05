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

// Структура для представления блока в CFG
typedef struct CFGBlock {
    int id;
    char* label;
    struct CFGBlock* next_true;  // для условных переходов (true ветвь)
    struct CFGBlock* next_false; // для условных переходов (false ветвь)
    struct CFGBlock* next;       // для последовательных переходов
} CFGBlock;

// Функция для создания нового блока CFG
CFGBlock* create_cfg_block(int* id_counter, const char* label);

// Функция для генерации CFG из AST функции
CFGBlock* generate_cfg_from_function(TSNode func_node, const char* source, int* id_counter);

// Функция для обработки statements
CFGBlock* process_statements(TSNode statements_node, const char* source, int* id_counter, CFGBlock* exit_block);

// Функция для обработки if statement
CFGBlock* process_if_statement(TSNode if_node, const char* source, int* id_counter, CFGBlock* exit_block);

// Функция для обработки loop statement
CFGBlock* process_loop_statement(TSNode loop_node, const char* source, int* id_counter, CFGBlock* exit_block);

// Функция для обработки repeat statement
CFGBlock* process_repeat_statement(TSNode repeat_node, const char* source, int* id_counter, CFGBlock* exit_block);

// Функция для создания нового блока CFG
CFGBlock* create_cfg_block(int* id_counter, const char* label) {
    CFGBlock* block = malloc(sizeof(CFGBlock));
    block->id = (*id_counter)++;
    block->label = strdup(label);
    block->next_true = NULL;
    block->next_false = NULL;
    block->next = NULL;
    return block;
}

// Функция для генерации CFG из AST функции
CFGBlock* generate_cfg_from_function(TSNode func_node, const char* source, int* id_counter) {
    CFGBlock* entry_block = create_cfg_block(id_counter, "Entry");

    // Найдем тело функции (repeat statement)
    uint32_t child_count = ts_node_child_count(func_node);
    TSNode body_statements = {0};
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(func_node, i);
        const char* type = ts_node_type(child);
        if (strcmp(type, "statement") == 0) {
            body_statements = child;
            break;
        }
    }

    if (!ts_node_is_null(body_statements)) {
        CFGBlock* exit_block = create_cfg_block(id_counter, "Exit");
        entry_block->next = process_statements(body_statements, source, id_counter, exit_block);
        return entry_block;
    }

    return entry_block;
}

// Функция для обработки statements
CFGBlock* process_statements(TSNode statements_node, const char* source, int* id_counter, CFGBlock* exit_block) {
    uint32_t child_count = ts_node_child_count(statements_node);
    CFGBlock* current_block = NULL;
    CFGBlock* first_block = NULL;

    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(statements_node, i);
        const char* type = ts_node_type(child);

        if (strcmp(type, "expression_statement") == 0) {
            // Создаем блок для выражения
            uint32_t start = ts_node_start_byte(child);
            uint32_t end = ts_node_end_byte(child);
            uint32_t len = end - start;
            char* stmt_text = malloc(len + 1);
            memcpy(stmt_text, source + start, len);
            stmt_text[len] = '\0';

            CFGBlock* stmt_block = create_cfg_block(id_counter, stmt_text);
            free(stmt_text);

            if (current_block) {
                current_block->next = stmt_block;
            } else {
                first_block = stmt_block;
            }
            current_block = stmt_block;
        } else if (strcmp(type, "if_statement") == 0) {
            // Обработка if statement
            CFGBlock* if_block = process_if_statement(child, source, id_counter, exit_block);
            if (current_block) {
                current_block->next = if_block;
            } else {
                first_block = if_block;
            }
            // После if, соединяем с exit через merge block
            CFGBlock* merge_block = create_cfg_block(id_counter, "Merge");
            merge_block->next = exit_block;
            current_block = merge_block;
        } else if (strcmp(type, "loop_statement") == 0) {
            // Обработка loop statement
            CFGBlock* loop_block = process_loop_statement(child, source, id_counter, exit_block);
            if (current_block) {
                current_block->next = loop_block;
            } else {
                first_block = loop_block;
            }
            current_block = NULL; // После loop, поток может не продолжаться последовательно
        } else if (strcmp(type, "repeat_statement") == 0) {
            // Обработка repeat statement
            CFGBlock* repeat_block = process_repeat_statement(child, source, id_counter, exit_block);
            if (current_block) {
                current_block->next = repeat_block;
            } else {
                first_block = repeat_block;
            }
            current_block = NULL;
        } else if (strcmp(type, "break_statement") == 0) {
            // Обработка break statement
            CFGBlock* break_block = create_cfg_block(id_counter, "break");
            break_block->next = exit_block; // break выходит из функции
            if (current_block) {
                current_block->next = break_block;
            } else {
                first_block = break_block;
            }
            current_block = NULL;
        }
    }

    if (current_block) {
        current_block->next = exit_block;
    } else if (!first_block) {
        first_block = exit_block;
    }

    return first_block;
}

// Функция для обработки if statement
CFGBlock* process_if_statement(TSNode if_node, const char* source, int* id_counter, CFGBlock* exit_block) {
    CFGBlock* condition_block = create_cfg_block(id_counter, "if condition");

    // Найдем condition, consequence и alternative
    TSNode condition = {0}, consequence = {0}, alternative = {0};
    uint32_t child_count = ts_node_child_count(if_node);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(if_node, i);
        const char* type = ts_node_type(child);
        if (strcmp(type, "expr") == 0) {
            condition = child;
        } else if (strcmp(type, "statement") == 0 && ts_node_is_null(consequence)) {
            consequence = child;
        } else if (strcmp(type, "statement") == 0 && !ts_node_is_null(consequence)) {
            alternative = child;
        }
    }

    // Создаем блоки для ветвей
    CFGBlock* true_block = process_statements(consequence, source, id_counter, exit_block);
    CFGBlock* false_block = ts_node_is_null(alternative) ? exit_block : process_statements(alternative, source, id_counter, exit_block);

    condition_block->next_true = true_block;
    condition_block->next_false = false_block;

    return condition_block;
}

// Функция для обработки loop statement
CFGBlock* process_loop_statement(TSNode loop_node, const char* source, int* id_counter, CFGBlock* exit_block) {
    CFGBlock* condition_block = create_cfg_block(id_counter, "loop condition");

    // Найдем condition и body
    TSNode condition = {0}, body = {0};
    uint32_t child_count = ts_node_child_count(loop_node);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(loop_node, i);
        const char* type = ts_node_type(child);
        if (strcmp(type, "expr") == 0) {
            condition = child;
        } else if (strcmp(type, "statement") == 0) {
            body = child;
        }
    }

    CFGBlock* body_block = process_statements(body, source, id_counter, condition_block); // тело ведет обратно к условию
    condition_block->next_true = body_block;
    condition_block->next_false = exit_block;

    return condition_block;
}

// Функция для обработки repeat statement
CFGBlock* process_repeat_statement(TSNode repeat_node, const char* source, int* id_counter, CFGBlock* exit_block) {
    CFGBlock* body_block = create_cfg_block(id_counter, "repeat body");

    // Найдем body и condition
    TSNode body = {0}, condition = {0};
    uint32_t child_count = ts_node_child_count(repeat_node);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(repeat_node, i);
        const char* type = ts_node_type(child);
        if (strcmp(type, "statement") == 0) {
            body = child;
        } else if (strcmp(type, "expr") == 0) {
            condition = child;
        }
    }

    CFGBlock* condition_block = create_cfg_block(id_counter, "repeat condition");
    condition_block->next_true = body_block; // если true, повторяем тело
    condition_block->next_false = exit_block; // если false, выходим

    body_block->next = condition_block; // после тела проверяем условие

    return body_block;
}

// Функция для генерации Mermaid диаграммы из CFG
char* generate_mermaid_from_cfg(CFGBlock* cfg) {
    char* diagram = NULL;
    append_to_diagram(&diagram, "graph TD;\n");

    // Рекурсивная функция для обхода CFG
    void traverse_cfg(CFGBlock* block) {
        if (!block) return;

        // Добавляем узел
        char node_line[256];
        sprintf(node_line, "B%d[\"%s\"]\n", block->id, block->label);
        append_to_diagram(&diagram, node_line);

        // Добавляем ребра
        if (block->next) {
            char edge_line[256];
            sprintf(edge_line, "B%d --> B%d\n", block->id, block->next->id);
            append_to_diagram(&diagram, edge_line);
            traverse_cfg(block->next);
        }
        if (block->next_true) {
            char edge_line[256];
            sprintf(edge_line, "B%d -->|true| B%d\n", block->id, block->next_true->id);
            append_to_diagram(&diagram, edge_line);
            traverse_cfg(block->next_true);
        }
        if (block->next_false) {
            char edge_line[256];
            sprintf(edge_line, "B%d -->|false| B%d\n", block->id, block->next_false->id);
            append_to_diagram(&diagram, edge_line);
            traverse_cfg(block->next_false);
        }
    }

    traverse_cfg(cfg);
    return diagram;
}

// Функция для генерации Mermaid диаграммы для функции (CFG)
char* generate_mermaid_for_function(TSNode func_node, const char* source) {
    int id_counter = 0;
    CFGBlock* cfg = generate_cfg_from_function(func_node, source, &id_counter);
    char* diagram = generate_mermaid_from_cfg(cfg);

    // Освобождение памяти CFG (упрощенная версия)
    // TODO: Реализовать полное освобождение памяти

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