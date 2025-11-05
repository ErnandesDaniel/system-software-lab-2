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
            // Пользовательский (кастомный) тип - идентификатор
            $.identifier, // custom: identifier;
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
            $.block_statement
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
            field('body', repeat(choice($.statement, $.source_item))),
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