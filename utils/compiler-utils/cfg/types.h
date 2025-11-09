#ifndef CFG_TYPES_H
#define CFG_TYPES_H

#include "../semantics-analysis/functions.h"
#include <stdint.h>
#include <stdbool.h>

//uint32_t → требует <stdint.h>
//bool → требует <stdbool.h>


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
    IR_RET,       // Возврат из функции (с значением или без)

    // === Операции с массивами ===
    IR_LOAD,   // Загрузка элемента: result = array[index]
    IR_SLICE   // Создание среза: result = array[start..end]
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

        // Загрузка элемента массива: result = array[index]
        struct {
            char result[64];
            Type* result_type;
            char array[64];  // имя переменной-массива
            char index[64];  // имя переменной-индекса
        } load;

        // Срез массива: result = array[start..end]
        struct {
            char result[64];
            Type* result_type;
            char array[64];
            char start[64];
            char end[64];    // может быть пустым
            bool has_end;
        } slice;
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

// Вспомогательная структура контекста построения графа потока управления
typedef struct CFGBuilderContext {

    CFG* cfg; // Ссылка на текущий объект графа управления

    BasicBlock* current_block; //Ссылка на текущий обрабатываемый блок

    const char* source_code;   // исходный текст всего файла с кодом

    int temp_counter;   //Счётчик для генерации уникальных временных имён переменных (имен типа t0, t1, t2...)

    int block_counter;  // Счётчик для генерации уникальных имён базовых блоков (имен типа BB_0, BB_1...)

    // Для break
    BlockId loop_exit_stack[32];

    int loop_depth;

    // Информация о текущей функции (из symbol table)
    FunctionInfo* current_function;

    // Локальные переменные текущей функции
    SymbolTable local_vars;

} CFGBuilderContext;

#endif