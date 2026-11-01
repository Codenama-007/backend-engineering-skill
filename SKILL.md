---
name: backend-engineering
description: >
  Design, implement, test, secure, and optimize backend applications.
  Use when building or modifying APIs, authentication, authorization,
  database models, migrations, background workers, caching, rate
  limiting, observability, or backend performance tests.
---

# Backend Engineering

## Objective

Implement reliable, secure, maintainable backend systems that fit
the existing project architecture.

Prioritize correctness, security, testability, and simplicity.

## 1. Inspect Before Implementing

Before modifying code:

- Identify the language, framework, and installed versions.
- Inspect the existing project structure and dependencies.
- Understand the database schema and migration strategy.
- Identify existing authentication and authorization mechanisms.
- Locate the current test suite and determine how to run it.
- Read existing project instructions.

Do not assume the project uses a particular framework or database.

## 2. Plan the Implementation

Before making substantial changes:

- Identify the requirements and acceptance criteria.
- Inspect existing code before proposing replacements.
- Identify relevant security and failure scenarios.
- Prefer the smallest implementation that satisfies the requirements.
- Explain significant architectural decisions.

Do not introduce infrastructure without a demonstrated need.

## 3. Authentication and Authorization

When implementing authentication:

- Distinguish authentication from authorization.
- Use established, maintained security libraries.
- Never store plaintext passwords.
- Validate credentials and session or token lifetimes.
- Keep secrets out of source control and logs.
- Protect sensitive endpoints with appropriate checks.
- Test unauthenticated and unauthorized requests.
- Test that one user cannot access another user's resources.

Never assume that hiding a frontend button provides security.

## 4. Database Engineering

- Inspect existing models and migration conventions.
- Define appropriate constraints and indexes.
- Use transactions for operations that require atomicity.
- Prevent SQL injection through parameterized queries or ORM APIs.
- Handle connection failures and transaction rollback correctly.
- Avoid N+1 queries where relevant.
- Never run destructive migrations without reviewing their impact.

## 5. Background Workers

When introducing background processing:

- Establish why synchronous processing is insufficient.
- Choose an appropriate queue and worker architecture.
- Make retry behavior explicit.
- Consider idempotency and duplicate task execution.
- Define timeouts and failure handling.
- Plan for monitoring and failed-task recovery.
- Keep long-running work outside latency-sensitive requests.

## 6. Caching

Before implementing caching:

- Identify the expensive operation being optimized.
- Define cache keys and their scope.
- Set appropriate expiration policies.
- Establish cache invalidation behavior.
- Consider stale data and concurrent updates.
- Prevent cross-user data leakage.
- Define what happens when the cache is unavailable.

Do not cache sensitive responses without evaluating their security
and isolation requirements.

## 7. Testing and Validation

For each change:

- Add or update relevant tests.
- Test success and failure paths.
- Test authorization boundaries when applicable.
- Test edge cases and concurrent behavior when relevant.
- Run the project's existing test suite.
- Run relevant linting and type checks.
- Report commands and their actual results honestly.

Never claim a test passed unless it was executed successfully.

## 8. Performance and Load Testing

Before optimizing:

- Establish a measurable performance objective.
- Identify relevant latency and throughput metrics.
- Use representative test data and request patterns.
- Measure the baseline before changing the implementation.
- Check error rates and resource utilization.
- Compare results after the change.
- Document test limitations.

Only run load tests against systems you own or are authorized
to test. Use explicit concurrency limits and request budgets.

## 9. Final Report

Summarize:

1. What changed.
2. Important design decisions.
3. Security considerations.
4. Tests executed and their results.
5. Performance implications, if measured.
6. Remaining risks or limitations.

Do not hide failed checks or unresolved issues.