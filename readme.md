
Запуск скомпилированного кода в Clion
./cmake-build-debug/system_software_lab_2 input.mylang ast.mmd cfg

установить зависимости Node.js:
npm install

Запуск генерации грамматики:
npx tree-sitter generate

src- исходники парсера

Конвертировать файл на языке mylang в S-expression формате в файл через стандартный инструмент библиотеки:
npx tree-sitter parse input.mylang > ast.json

<-------Использование GCC компилятора----------->

Установить gcc комплиятор на свою среду

Проверить через gcc --version

Скомпилировать в исполняемый можно через:
gcc -o main main.c lib/cJSON/cJSON.c

Windows PowerShell:

gcc -std=c17 `
  -Ilib/tree-sitter/lib/include `
-Ilib/tree-sitter/lib/src `
  -Ilib/cJSON `
-o main.exe `
  main.c `
lib/tree-sitter/lib/src/lib.c `
  src/parser.c `
lib/cJSON/cJSON.c

Запустить можно через
./main input.mylang ast.json


<-------Использование CMake системы сборки----------->

Скомпилировать в CLion

Далее можно запустить программу:
./cmake-build-debug/system_software_lab_2 input.mylang ast.mmd cfg

mono runtime - нужно скачать для третьей лабораторной или использовать готовое remote tasks для windows

аргументы можно передать или через переменные окружения или через аргументы командной строки

ключ а - можно узнать что можно с помощью этой утилиты делать

полевая конверныция системы вызовов

linux64 abi.pdf

function call


для каждой функции в главном файле свой граф потока управления в отдельном файле

для графа потока управления

английская версия википедии граф потока управления

dgml

dot

книга

380 страница engenering compilers, граф потока управления

книга Серебряков, можно просмотреть

173 страница трансляция выражений














у меня есть грамматика моего языка программирования, записанная в tree setter

//Основные функции:
// Используется для определения повторяющихся последовательностей элементов (0 или более)

//repeat

// Используется для определения необязательных элементов

//optional

// Используется для определения альтернатив (один из)

//choice

// Используется для определения последовательностей элементов

//seq

// Используется для определения терминала, который не может быть частью другого терминала (например, идентификатор, не являющийся ключевым словом).
// Требуется для разрешения конфликтов между идентификаторами и ключевыми словами.

//prec

// Используется для указания приоритета и ассоциативности операторов.
// prec.left() - левоассоциативный оператор
// prec.right() - правоассоциативный оператор
// prec.dynamic() - динамический приоритет

// Используется для определения регулярных выражений для лексем (токенов).
// Обычно используется для идентификаторов, чисел, строк.

//token,

// Используется для определения строковых литералов (ключевые слова).
// Аналогично token(string), но часто используется для ключевых слов.
// Мы будем использовать token() для ключевых слов.
// field - позволяет задавать именованные поля в узлах AST для лучшего доступа к дочерним элементам.
// field('name', rule) - добавляет поле 'name' к результату правила 'rule'.
// Используется для улучшения структуры AST.

//field,

// $ - псевдоним для объекта правил грамматики (GRAMMAR).
// $ - это объект, в который добавляются все правила (start, rules, word, extras, conflicts, precedences).
// Внутри функции grammar() $ - это аргумент, который нужно вернуть.


// Основная функция, определяющая грамматику.

// Она возвращает объект с конфигурацией грамматики.

// Правило списка соответствует: (item (',' item)*)?

module.exports = grammar({

    // Имя грамматики. Используется для идентификации.
    name: 'mylang',

    // Пробелы и переносы строк игнорируются
    extras: $ => [/\s/],

    word: $ => $.identifier,

    conflicts: $ => [
        [ $.parenthesized_expr, $.list_expr]
    ],

    // Правила грамматики. Это основная часть, определяющая структуру языка.
    rules: {

        // source: sourceItem*;
        // Корень программы. Состоит из нуля или более sourceItem (обычно это определения функций)
        //Это правило должно быть первым, так как с него начинается разбор файла
        source: $ => repeat($.source_item),

        // sourceItem: {
        // |funcDef: 'def' funcSignature statement* 'end';
        // };
        // Определение элемента исходного кода. В текущей грамматике только функции.
        // funcDef: 'def' funcSignature statement* 'end';
        source_item: $ => seq(
            // Ключевое слово 'def' как идентификатор объявления функции
            'def',
            // Далее следует сигнатура функции
            field('signature', $.func_signature),

            // Ноль или более операторов внутри тела функции
            field('body', repeat($.statement)),

            // Ключевое слово 'end', закрывающее тело функции
            'end'
        ),

        // funcSignature: identifier '(' list<arg> ')' ('of' typeRef)?;
        // Сигнатура функции: имя, список аргументов, опционально - тип возвращаемого значения.
        func_signature: $ => seq(
            // Имя функции (идентификатор)
            field('name', $.identifier),
            // Открывающая скобка
            '(',
            // Список аргументов, определенный как list<arg>
            field('parameters', optional($.list_arg)),
            // Закрывающая скобка
            ')',
            // Необязательный тип возвращаемого значения, начинающийся с 'of'
            optional(seq('of', field('return_type', $.type_ref)))
        ),

        // list<item>: (item (',' item)*)?;
        // Общий шаблон для списка элементов, разделенных запятыми.
        // list<arg> для аргументов функции
        list_arg: $ =>field('elements',
            seq(
                $.arg, // Первый элемент
                repeat( // Повторяющийся паттерн: запятая и следующий элемент
                    seq(',', $.arg)
                )
        )),

        // arg: identifier ('of' typeRef)?;
        // Определение аргумента функции: имя и опциональный тип.
        arg: $ => seq(
            // Имя аргумента (идентификатор)
            field('name', $.identifier),
            // Необязательная спецификация типа, начинающаяся с 'of'
            optional(seq('of', field('type', $.type_ref)))
        ),

        // typeRef: {
        // |builtin: 'bool'|'byte'|'int'|'uint'|'long'|'ulong'|'char'|'string';
        // |custom: identifier;
        // |array: typeRef 'array' '[' dec ']'; // число - размерность
        // };
        // Ссылка на тип данных.
        type_ref: $ => choice(
            // Встроенные (базовые) типы
            $.builtin_type,
            // Массив заданного типа с фиксированным размером
            seq(
                // Базовый тип массива
                field('element_type', $.type_ref),
                // Ключевое слово 'array'
                'array',
                // Открывающая квадратная скобка
                '[',
                // Размерность массива (десятичное число)
                field('size', $.dec),
                // Закрывающая квадратная скобка
                ']'
            )
        ),

        // builtin: 'bool'|'byte'|'int'|'uint'|'long'|'ulong'|'char'|'string';
        // Встроенные типы данных. Выделены в отдельное правило для читаемости.
        builtin_type: $ => choice(
            'bool', 'byte', 'int', 'uint', 'long', 'ulong', 'char', 'string'
        ),

        // Регулярное выражение для идентификатора
        identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*/,

        // str: "\"[^\"\\]*(?:\\.[^\"\\]*)*\"";
        str: $ => token(seq('"', /[^"\\]*(?:\\.[^"\\]*)*/, '"')), // Строковый литерал в двойных кавычках с экранированием

        // char: "'[^']'";
        char: $ => token(seq("'", /[^']/, "'")), // Символьный литерал в одинарных кавычках

        // hex: "0[xX][0-9A-Fa-f]+";
        hex: $ => token(/0[xX][0-9A-Fa-f]+/), // Шестнадцатеричный литерал

        // bits: "0[bB][01]+";
        bits: $ => token(/0[bB][01]+/), // Битовый литерал

        // dec: "[0-9]+";
        dec: $ => token(/[0-9]+/), // Десятичный литерал

        // bool: 'true'|'false';
        bool: $ => choice('true', 'false'), // Булевский литерал

        // statement:
        statement: $ => choice(
            $.if_statement,
            $.loop_statement,
            $.repeat_statement,
            $.break_statement,
            $.expression_statement,
            $.block_statement,
            $.return_statement
        ),

        return_statement: $ => seq(
            'return',
            optional($.expr), // может быть return; или return expr;
            ';'
        ),

        // if: 'if' expr 'then' statement ('else' statement)?;
        if_statement: $ => prec.right(seq(
            'if',
            field('condition', $.expr),
            'then',
            field('consequence', $.statement),
            optional(seq('else', field('alternative', $.statement)))
        )),

        // loop: ('while'|'until') expr statement* 'end';
        loop_statement: $ => seq(
            field('keyword', choice('while', 'until')),
            field('condition', $.expr),
            field('body', repeat($.statement)),
            'end'
        ),

        // repeat: statement ('while'|'until') expr ';';
        repeat_statement: $ => prec(1,seq(
            field('body', $.statement),
            field('keyword', choice('while', 'until')),
            field('condition', $.expr),
            ';'
        )),

        // break: 'break' ';';
        break_statement: $ => seq('break', ';'),

        // expression: expr ';';
        expression_statement: $ => seq(
            field('expression', $.expr), ';'
        ),

        // block: ('begin'|'{') (statement|sourceItem)* ('end'|'}');
        block_statement: $ => seq(
            choice('begin', '{'),
            field('body', repeat($.statement)),
            choice('end', '}')
        ),

        // expr: binary_expr
        //     | unary_expr
        //     | parenthesized_expr
        //     | call_expr
        //     | slice_expr
        //     | identifier
        //     | literal;
        // Корневое правило для выражений. Охватывает все возможные формы выражений
        // в языке: операции, вызовы, литералы и переменные.
        expr: $ => choice(
            $.binary_expr,
            $.unary_expr,
            $.parenthesized_expr,
            $.call_expr,
            $.slice_expr,
            $.identifier,
            $.literal
        ),


        // binary_expr: expr ('*' | '/' | '%') expr
        //             | expr ('+' | '-') expr
        //             | expr ('<' | '>' | '==' | '!=' | '<=' | '>=') expr
        //             | expr '&&' expr
        //             | expr '||' expr
        //             | expr '=' expr;
        // Бинарные операторы с явным указанием приоритетов и ассоциативности.
        // Приоритеты убывают сверху вниз; присваивание — правоассоциативное.
        binary_expr: $ => choice(
            prec.left(2, seq(
                field('left', $.expr),
                field('operator', choice('*', '/', '%')),
                field('right', $.expr)
            )),
            prec.left(1, seq(
                field('left', $.expr),
                field('operator', choice('+', '-')),
                field('right', $.expr)
            )),
            prec.left(0, seq(
                field('left', $.expr),
                field('operator', choice('<', '>', '==', '!=', '<=', '>=')),
                field('right', $.expr)
            )),
            prec.left(-1, seq(
                field('left', $.expr),
                field('operator', '&&'),
                field('right', $.expr)
            )),
            prec.left(-2, seq(
                field('left', $.expr),
                field('operator', '||'),
                field('right', $.expr)
            )),
            prec.right(-3, seq(
                field('left', $.expr),
                field('operator', '='),
                field('right', $.expr)
            ))
        ),

        // unary_expr: ('-' | '+' | '!' | '~') expr;
        // Унарные операторы. Правоассоциативны: -!x разбирается как -( !x ).
        unary_expr: $ => prec.right(3, seq(
            field('operator', choice('-', '+', '!', '~')),
            field('operand', $.expr)
        )),

        // parenthesized_expr: '(' expr ')';
        // Группировка подвыражения с помощью скобок для переопределения приоритета.
        parenthesized_expr: $ => seq('(', $.expr, ')'),

        // call_expr: expr '(' list_expr ')';
        // Вызов функции: выражение, за которым следует список аргументов в скобках.
        call_expr: $ => seq(
            field('function', $.expr),
            '(',
            field('arguments', optional($.list_expr)),
            ')'
        ),

        // list<expr> для аргументов вызова функции
        list_expr: $ =>seq(
                $.expr, // Первое выражение
                repeat( // Повторяющийся паттерн: запятая и следующее выражение
                    seq(',', $.expr)
                )
        ),

        // slice_expr: expr '[' list_range ']';
        // Доступ к элементам массива или срез: может содержать один или несколько
        // индексов или диапазонов, разделённых запятыми.
        slice_expr: $ => seq(
            field('array', $.expr),
            '[',
            field('ranges', optional($.list_range)),
            ']'
        ),

        // list<range> для срезов массива
        list_range: $ => seq(
                $.range, // Первый диапазон
                repeat( // Повторяющийся паттерн: запятая и следующий диапазон
                    seq(',', $.range)
                )
        ),

        // range: expr ('..' expr)?;
        // Диапазон для среза массива: expr ('..' expr)? - начальный индекс и опциональный конечный индекс
        range: $ => seq(
            field('start', $.expr), // Начальный индекс
            optional(seq('..', field('end', $.expr))) // Опциональный конечный индекс
        ),


        // literal: bool | str | char | hex | bits | dec;
        // Атомарные значения, не содержащие подвыражений.
        literal: $ => choice(
            $.bool,
            $.str,
            $.char,
            $.hex,
            $.bits,
            $.dec
        ),
    },
});

я использую библиотеку tree setter чтобы получить ast дерево

    TSParser *parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_mylang());

    TSTree *tree = ts_parser_parse_string(parser, NULL, content, file_size);
    
    const TSNode root_node = ts_tree_root_node(tree);

я создал объявления интерфейсов для создания графа потока управления на основе кода программы на моем языке, вот интерфейс элементов графа потока управления:

#include <stdint.h>
#include <stdbool.h>

//uint32_t → требует <stdint.h>
//bool → требует <stdbool.h>



//Типы данных

typedef enum {
TYPE_BOOL,      // 'bool'
TYPE_INT,       // 'byte', 'int', 'uint', 'long', 'ulong', 'char', и все числовые литералы
TYPE_STRING,    // 'string'
TYPE_VOID,      // для функций
TYPE_ARRAY,     // массив
} TypeKind;

typedef struct Type {
TypeKind kind;
union {
struct {
struct Type* element_type;  // тип элементов массива
uint32_t size;                   // количество элементов
} array_info;  // это только для массивов!
} data;
} Type;

// Операнды

//Эта структура описывает один аргумент (операнд) для IR-инструкции

// IR-инструкции работают с переменными и константами. Операнд — это один аргумент инструкции.

typedef enum {
OPERAND_CONST,  // литерал: 42, "hello", true
OPERAND_VAR     // переменная: x, t1, result
} OperandKind;


// Структура для хранения значения константы
typedef struct ConstValue {
Type* type;              // тип: int, bool, string и т.д.
union {
int32_t integer;     // для всех целых: bool, byte, char, int, uint, long, ulong, dec, hex, bits
char*   string;      // для str — уже без кавычек, с обработанными \n, \", и т.д.
} value;
} ConstValue;


typedef struct Operand {
OperandKind kind;
union {
ConstValue const_val;   // значение константы
struct {
char* name;         // имя переменной "x", "temp", "a"
Type* type;         // тип переменной
} var;
} data;
} Operand;


// Опкоды IR-инструкций — элементарные операции промежуточного представления
typedef enum {
// === Арифметические операции ===
IR_ADD,  // Сложение: result = left + right
IR_SUB,  // Вычитание: result = left - right
IR_MUL,  // Умножение: result = left * right
IR_DIV,  // Деление: result = left / right

    // === Операции сравнения (возвращают bool) ===
    IR_EQ,   // Equal — равно: result = (left == right)
    IR_NE,   // Not Equal — не равно: result = (left != right)
    IR_LT,   // Less Than — меньше: result = (left < right)
    IR_LE,   // Less or Equal — меньше или равно: result = (left <= right)
    IR_GT,   // Greater Than — больше: result = (left > right)
    IR_GE,   // Greater or Equal — больше или равно: result = (left >= right)

    // === Логические операции (работают с bool) ===
    IR_AND,  // Логическое И: result = left && right
    IR_OR,   // Логическое ИЛИ: result = left || right

    // === Унарные операции ===
    IR_NOT,   // Логическое НЕ: result = !operand
    IR_NEG,   // Унарный минус: result = -operand
    IR_POS,   // Унарный плюс: result = +operand (обычно ничего не делает, но синтаксически есть)
    IR_BIT_NOT,  // Побитовое НЕ: result = ~operand

    // === Присваивание ===
    IR_ASSIGN,  // Присвоить значение переменной: var = value

    // === Вызов функции ===
    IR_CALL,    // Вызвать функцию: result = func(arg1, arg2, ...)

    // === Управление потоком выполнения (обычно только в конце базового блока) ===
    IR_JUMP,     // Безусловный переход к указанному блоку (аналог goto)
    //IR_COND_BR — слово BR — это сокращение от «branch»
    IR_COND_BR,  // Условный переход: если условие истинно → блок A, иначе → блок B
    IR_RET       // Возврат из функции (с значением или без)
} IROpcode;


typedef char BlockId[64]; // уникальное имя блока: "BB_0", "if_then", и т.д.

typedef struct IRInstruction {
IROpcode opcode;
union {

        // Для вычислений: результат + операнды

        //compute — для вычисляющих операций (IR_ADD, IR_EQ, IR_CALL и т.д.)

        struct {
            char result[64];      // Куда (имя) сохранить результат: "t1", "x"
            Type* result_type;    // Тип результата: int, bool, и т.д.
            Operand operands[2];  // Аргументы операции (обычно 1 или 2)
            int num_operands;     // Сколько операндов реально используется
        } compute;

        // Безусловный переход: goto метка
        struct {
            BlockId target; // Куда прыгать: "BB_exit", "loop_start"
        } jump;

        // Условный переход: if (cond) goto A else goto B
        struct {
            Operand condition;    // Условие: переменная или константа типа bool
            BlockId true_target;  // Куда прыгать, если условие истинно
            BlockId false_target; // Куда прыгать, если ложно
        } cond_br;

        // Возврат
        struct {
            Operand value;     // Возвращаемое значение (может быть неиспользуемым)
            bool has_value;    // true — функция возвращает значение, false — void
        } ret;

        // Вызов функции
        struct {
            char result[64];      // Куда сохранить результат ("" если void)
            Type* result_type;    // Тип возвращаемого значения
            char func_name[64];   // Имя вызываемой функции: "print", "sqrt"
            Operand args[16];     // Список аргументов (макс. 16 — для простоты)
            int num_args;         // Сколько аргументов реально передаётся
        } call;

        // Присваивание
        struct {
            char target[64];   // имя переменной, которой присваиваем (например, "x")
            Operand value;     // значение, которое присваиваем (например, константа 5)
        } assign;

        // Унарные операции — работают с одним операндом
        // используются для: !x, -x, +x, ~x
        struct {
            char result[64];      // Имя переменной для сохранения результата (например, "t1")
            Type* result_type;    // Тип результата (должен соответствовать операции и операнду)
            Operand operand;      // Единственный входной операнд (например, переменная "x" или константа)
        } unary;
    } data;
} IRInstruction;



// Базовый блок

#define MAX_INSTRUCTIONS 256  // достаточно для большинства блоков
#define MAX_SUCCESSORS 4      // максимальное число исходящих переходов (обычно 1 или 2)

typedef struct BasicBlock {

    BlockId id;                              // уникальный ID блока: "BB_0"

    IRInstruction instructions[MAX_INSTRUCTIONS]; //массив IR-инструкций блока

    size_t num_instructions; //сколько инструкций реально используется в массиве, чтобы не обрабатывать "мусор" в конце массива

    BlockId successors[MAX_SUCCESSORS]; // список ID блоков, в которые можно перейти после выполнения этого блока (это рёбра графа потока управления)

    size_t num_successors; // сколько преемников реально есть.
} BasicBlock;

//Граф потока управления

//Это вся функция целиком: все блоки + связи между ними.
//Из CFG потом генерируется ассемблер с метками и переходами.

#define MAX_BLOCKS 1024  // достаточно для одной функции

typedef struct CFG {

    BlockId entry_block_id;    // с какого блока начинать выполнение

    BasicBlock blocks[MAX_BLOCKS]; //массив блоков

    size_t num_blocks; //сколько реально блоков используется

} CFG;

у меня есть типы данных для создания графа потока управления

мне нужно создать граф потока управления из ast дерева, для этого нужна функция cfg_build_from_ast











