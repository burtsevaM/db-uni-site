# Blind SQL-инъекция

## 1. Результат уязвимости

На странице пользовательских SQL-отчетов в поле `WHERE fragment` вводились логические условия. Если условие было истинным, сайт показывал строки отчета. Если условие было ложным, в результате было написано, что данных для отображения нет.

При blind SQL-инъекции данные напрямую не выводятся через ошибку или отдельную строку. Их приходится угадывать по реакции сайта. В этой демонстрации реакцией было появление или отсутствие строк в отчете.

Через такие проверки можно было узнать, есть ли пользовательские таблицы в базе, сколько их примерно и какие символы есть в названиях таблиц. Например, по проверке отдельных символов было видно, что первое имя таблицы начинается с `app_`.

![Демонстрация blind SQL-инъекции](./4v.gif)

## 2. Как была найдена уязвимость

1. Открыла страницу `SQL Reports` под пользователем `alice`.

2. Сначала проверила истинное условие:

```sql
1=1
```

Такое условие всегда истинное, поэтому отчет возвращал строки. Это показало, что введенный текст используется как часть SQL-условия.

3. Затем проверила ложное условие:

```sql
1=0
```

На демонстрации для такой же проверки использовалось `1=2`. Условие ложное, поэтому строки отчета не показывались. Это подтвердило, что результат зависит от введенного SQL-фрагмента.

4. После этого была проверка наличия пользовательских таблиц:

```sql
1=1 AND EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog','information_schema')
)
```

Если после запуска отчета строки появлялись, значит такие таблицы в базе есть.

5. Потом проверялось количество таблиц через логическое сравнение:

```sql
1=1 AND (
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog','information_schema')
) > 4
```

Если условие `> 4` давало строки, а более большое число уже не давало строки, можно было понять количество таблиц. Так постепенно угадывается число, хотя сайт его напрямую не выводит.

6. Затем проверялись отдельные символы названия первой таблицы:

```sql
1=1 AND SUBSTRING((
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog','information_schema')
    ORDER BY table_name
    LIMIT 1 OFFSET 0
), 1, 1) = 'a'
```

Если строки появлялись, значит первый символ названия таблицы равен `a`.
Тк в error-based инъекциях бы уже нашли названия таблиц, я решила проверить работает ли blind sql инъекция на таблице app_users. 

7. Таким же способом проверялись следующие символы:

```sql
1=1 AND SUBSTRING((
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog','information_schema')
    ORDER BY table_name
    LIMIT 1 OFFSET 0
), 4, 1) = '_'
```

Если условие было истинным, отчет снова показывал строки. Так можно было посимвольно восстановить название таблицы. В демонстрации было видно, что имя первой таблицы начинается с `app_`.

## 3. Причина уязвимости

Причина была в том, что приложение принимало от пользователя произвольный фрагмент `WHERE` и передавало его в функцию отчета. В серверном коде проверялось только то, что строка не пустая, а затем значение отправлялось в базу:

![Передача произвольного WHERE-фрагмента](<./Снимок экрана 2026-05-26 в 3.47.47 PM.png>)

Также обработчик страницы брал значение `whereClause` прямо из формы и возвращал пользователю результат отчета:

![Обработчик формы до исправления](<./Снимок экрана 2026-05-26 в 3.48.29 PM.png>)

Основная проблема находилась в SQL-функции `training.run_custom_report(raw_where_clause text)`. В ней пользовательский фрагмент подставлялся в запрос через `format(... WHERE %s ...)` и выполнялся через `EXECUTE`. Поэтому введенный текст становился частью SQL-команды:

### Код до исправления

Серверная функция принимала строку `whereClause` и передавала ее в базу как параметр. На этом уровне параметризация выглядела безопасно, но дальше в базе строка использовалась как SQL-фрагмент:

```typescript
export async function runCustomReport(whereClause: string) {
    if (!whereClause.trim()) {
        error(400, 'WHERE clause is required');
    }

    const result = await pool.query('SELECT * FROM training.run_custom_report($1)', [whereClause]);
    return result.rows;
}
```

В SQL-функции `raw_where_clause` попадал в `format(... WHERE %s ...)` и выполнялся через `EXECUTE`:

```sql
CREATE OR REPLACE FUNCTION training.run_custom_report(raw_where_clause text)
RETURNS TABLE (
    customer_name text,
    amount numeric,
    owner_name text,
    card_hint text
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY EXECUTE format(
        'SELECT c.full_name, i.amount, u.full_name, i.card_hint
         FROM training.invoices i
         JOIN training.customers c ON c.id = i.customer_id
         JOIN training.app_users u ON u.id = i.owner_user_id
         WHERE %s
         ORDER BY i.id',
        raw_where_clause
    );
END;
$$;
```

Дополнительно у роли приложения был включен обход RLS:

```sql
ALTER ROLE app_user BYPASSRLS;
```

![Уязвимая SQL-функция отчета](<./Снимок экрана 2026-05-26 в 3.46.22 PM.png>)

Дополнительно роль `app_user` имела `BYPASSRLS`, то есть могла обходить политики Row Level Security:

![Роль с обходом RLS](<./Снимок экрана 2026-05-26 в 3.47.00 PM.png>)

Из-за этого пользователь мог добавлять в условие подзапросы к `information_schema` и получать ответы по принципу true/false: есть строки в отчете или нет.

## 4. Исправление

После исправления приложение больше не принимает произвольный SQL-фрагмент. Вместо одного поля `WHERE fragment` используются отдельные безопасные параметры фильтрации: имя владельца, статус и минимальная сумма.

В серверном коде появилась структура фильтров, а вызов отчета стал параметризованным:

### Код после исправления

В серверном коде появились конкретные поля фильтрации. Значения передаются в SQL-функцию отдельными параметрами, а не склеиваются в условие `WHERE`:

```typescript
type ReportFilters = {
    ownerUsername?: string;
    status?: string;
    minAmount?: number | null;
};

export async function runCustomReport(filters: ReportFilters) {
    const ownerUsername = filters.ownerUsername?.trim() || null;
    const status = filters.status?.trim() || null;
    const minAmount = filters.minAmount ?? null;

    const result = await pool.query(
        'SELECT * FROM training.run_custom_report($1, $2, $3)',
        [ownerUsername, status, minAmount]
    );

    return result.rows;
}
```

Обработчик формы проверяет статус и отдельно приводит минимальную сумму к числу:

```typescript
const ownerUsername = String(form.get('ownerUsername') ?? '').trim();
const status = String(form.get('status') ?? '').trim();
const minAmountRaw = String(form.get('minAmount') ?? '').trim();

if (status && !allowedStatuses.has(status)) {
    return fail(400, {
        ownerUsername,
        status,
        minAmount: minAmountRaw,
        error: 'Недопустимый статус отчета'
    });
}

const minAmount = minAmountRaw ? Number(minAmountRaw) : null;

if (minAmountRaw && Number.isNaN(minAmount)) {
    return fail(400, {
        ownerUsername,
        status,
        minAmount: minAmountRaw,
        error: 'Минимальная сумма должна быть числом'
    });
}

const results = await runCustomReport({
    ownerUsername,
    status,
    minAmount
});
```

![Параметризованный вызов отчета](<./Снимок экрана 2026-05-26 в 3.47.54 PM.png>)

В обработчике формы теперь отдельно читаются поля `ownerUsername`, `status` и `minAmount`. Статус проверяется по списку разрешенных значений, а минимальная сумма приводится к числу:

![Обработчик формы после исправления](<./Снимок экрана 2026-05-26 в 3.48.37 PM.png>)

SQL-функция отчета тоже была переписана. Она больше не принимает `raw_where_clause` и не выполняет динамический SQL через `EXECUTE`. Вместо этого она принимает обычные параметры и использует их в статическом запросе:

```sql
CREATE OR REPLACE FUNCTION training.run_custom_report(
    report_owner_username text DEFAULT NULL,
    report_status text DEFAULT NULL,
    min_amount numeric DEFAULT NULL
)
RETURNS TABLE (
    customer_name text,
    amount numeric,
    owner_name text,
    card_hint text
)
LANGUAGE sql
SECURITY INVOKER
AS $$
    SELECT c.full_name, i.amount, u.full_name, i.card_hint
    FROM training.invoices i
    JOIN training.customers c ON c.id = i.customer_id
    JOIN training.app_users u ON u.id = i.owner_user_id
    WHERE
        (report_owner_username IS NULL OR u.username = report_owner_username)
        AND (report_status IS NULL OR i.status = report_status)
        AND (min_amount IS NULL OR i.amount >= min_amount)
    ORDER BY i.id;
$$;
```

![Исправленная SQL-функция отчета](<./Снимок экрана 2026-05-26 в 3.46.52 PM.png>)

Также для роли `app_user` был отключен обход RLS:

```sql
ALTER ROLE app_user NOBYPASSRLS;
```

![Отключение обхода RLS](<./Снимок экрана 2026-05-26 в 3.47.12 PM.png>)

Теперь пользовательский ввод не становится частью SQL-команды. Даже если ввести выражения вроде `1=1 AND SUBSTRING(...)`, они не будут выполнены как SQL-условие отчета.

## 5. Вывод

Blind SQL-инъекция позволяла получать информацию о базе без прямого вывода данных. Пользователь мог задавать условия и по реакции сайта понимать, истинны они или ложны.

Для исправления нужно не принимать от пользователя произвольные SQL-фрагменты. Вместо этого надо использовать конкретные поля фильтрации, проверять их на сервере и передавать значения в базу через параметры.
