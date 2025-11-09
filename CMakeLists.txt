cmake_minimum_required(VERSION 4.0)
project(system_software_lab_2 C)

set(CMAKE_C_STANDARD 17)

# Указываем, какие файлы компилировать
add_executable(system_software_lab_2
        main.c

        utils/common-utils/common-utils.c
        utils/mermaid-utils/mermaid-utils.c

        utils/compiler-utils/ast/ast.c
        utils/compiler-utils/cfg/block_manage.c
        utils/compiler-utils/cfg/cfg.c
        utils/compiler-utils/cfg/expressions.c
        utils/compiler-utils/cfg/loop_context.c
        utils/compiler-utils/cfg/mermaid.c
        utils/compiler-utils/cfg/statements.c
        utils/compiler-utils/cfg/types.c
        utils/compiler-utils/cfg/utils.c

        utils/compiler-utils/semantics-analysis/semantics-analysis.c
        utils/compiler-utils/semantics-analysis/types.c
        utils/compiler-utils/semantics-analysis/symbol.c
        utils/compiler-utils/semantics-analysis/functions.c

        lib/tree-sitter/lib/src/lib.c # библиотека tree-sitter
        src/parser.c # сгенерированный для языка mylang парсер
)

# Указываем, где искать заголовки
target_include_directories(system_software_lab_2 PRIVATE
        lib/tree-sitter/lib/include        # ← здесь лежит api.h библиотеки tree-sitter
        lib/tree-sitter/lib/src            # ← здесь лежат alloc.c, parser.c и т.д. библиотеки tree-sitter
        utils
)








