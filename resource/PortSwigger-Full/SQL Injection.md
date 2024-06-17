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