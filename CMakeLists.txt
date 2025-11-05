cmake_minimum_required(VERSION 4.0)
project(system_software_lab_2 C)

set(CMAKE_C_STANDARD 17)

# Указываем, какие файлы компилировать
add_executable(system_software_lab_2
        main.c
        utils/common-utils/common-utils.c
        utils/mermaid-utils/mermaid-utils.c
        lib/tree-sitter/lib/src/lib.c # библиотека tree-sitter
        src/parser.c # сгенерированный для языка mylang парсер
)

# Указываем, где искать заголовки
target_include_directories(system_software_lab_2 PRIVATE
        lib/tree-sitter/lib/include        # ← здесь лежит api.h библиотеки tree-sitter
        lib/tree-sitter/lib/src            # ← здесь лежат alloc.c, parser.c и т.д. библиотеки tree-sitter
        utils
)








