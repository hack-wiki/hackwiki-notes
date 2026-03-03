% Filename: 04-web-testing/api-testing/overview.md
% Display name: API Testing Overview
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# API Testing

## Overview

API testing targets the programmatic interfaces that applications expose — REST endpoints, GraphQL schemas, and WebSocket connections. APIs often have weaker security controls than browser-facing pages because developers assume only their front-end will interact with them. This makes APIs a high-value attack surface for authentication bypass, data exposure, and privilege escalation.

## Topics in This Section

- [REST API Testing](rest-api.md) — endpoint discovery, authentication testing, BOLA/IDOR, mass assignment, rate limiting bypass, verbose error exploitation
- [GraphQL Testing](graphql.md) — introspection queries, authorization bypass, batching attacks, injection, denial of service via nested queries
- [WebSocket Testing](websocket.md) — connection hijacking, cross-site WebSocket hijacking (CSWSH), message injection, origin validation bypass
