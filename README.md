# Backend Engineering Skill

A reusable, cross-agent backend engineering skill that helps AI coding agents build, secure, test, and optimize backend applications with a consistent engineering workflow.

Designed for **Codex**, **Claude Code**, and **OpenCode**, the project combines reusable instructions, focused technical references, validation scripts, and evaluation scenarios. The goal is not simply to generate backend code, but to help agents make sound engineering decisions and verify their work.

> **Status:** Early-stage project. Features, supported stacks, and installation workflows may evolve as the skill is developed and evaluated.

## Why this project?

Backend tasks often require more than generating an endpoint. Reliable implementations need to account for security, data integrity, failure handling, testing, performance, and maintainability.

Backend Engineering Skill aims to give coding agents a repeatable workflow for:

- Inspecting an existing codebase before making changes.
- Choosing solutions appropriate to the project's architecture and requirements.
- Implementing backend features with security and reliability in mind.
- Testing success paths, failure paths, and authorization boundaries.
- Running relevant validation and reporting actual results.
- Avoiding unnecessary infrastructure and unsupported claims about test results.

## Core principles

- **Inspect before implementing:** Respect the project's existing stack, conventions, and architecture.
- **Security by design:** Treat authentication, authorization, input validation, and secret handling as first-class requirements.
- **Prefer simplicity:** Introduce infrastructure only when requirements justify it.
- **Test the behavior:** Verify edge cases and failure scenarios, not just happy paths.
- **Measure performance:** Establish a baseline before optimizing.
- **Be transparent:** Report executed checks, failures, limitations, and unresolved risks honestly.
- **Load context selectively:** Keep the main skill concise and place detailed guidance in focused reference files.

## Planned capabilities

| Area | Intended coverage |
|---|---|
| Backend foundations | API design, validation, error handling, configuration, and project conventions |
| Authentication | Password handling, sessions, tokens, and authentication lifecycles |
| Authorization | Roles, permissions, resource-level checks, and multi-tenant isolation |
| Database engineering | Models, constraints, transactions, migrations, indexes, and query optimization |
| Background workers | Queues, retries, idempotency, timeouts, and failed-task recovery |
| Caching | Cache keys, TTL, invalidation, consistency, and isolation |
| API security | Rate limiting, CORS/CSRF where applicable, secret handling, and security tests |
| Observability | Structured logs, metrics, health checks, and tracing |
| Performance testing | Load tests, latency percentiles, throughput, error rates, and bottleneck analysis |
| Production readiness | Containers, CI/CD, deployment checks, rollback, and recovery planning |

These are planned areas, not a claim that every capability is already implemented.

## How it works

The skill follows a repeatable engineering workflow:

1. **Inspect** the project structure, framework versions, dependencies, database, and tests.
2. **Plan** the smallest change that satisfies the requirements and acceptance criteria.
3. **Design** the solution, including relevant security and failure cases.
4. **Implement** using the project's conventions and suitable maintained libraries.
5. **Test** the change with appropriate unit, integration, and security tests.
6. **Validate** using available test, lint, type-check, and migration checks.
7. **Review** for regressions, security risks, concurrency issues, and unnecessary complexity.
8. **Report** changes, decisions, checks actually run, and remaining limitations.

The agent should apply only the guidance relevant to the current task rather than loading every reference for every request.

## Repository structure

The following is the intended structure; files may be added as the project develops.

```text
backend-engineering-skill/
├── README.md
├── LICENSE
├── skills/
│   └── backend-engineering/
│       ├── SKILL.md
│       ├── references/
│       │   ├── architecture.md
│       │   ├── authentication.md
│       │   ├── authorization.md
│       │   ├── database-design.md
│       │   ├── background-workers.md
│       │   ├── caching.md
│       │   ├── api-security.md
│       │   ├── observability.md
│       │   └── performance-testing.md
│       ├── templates/
│       │   ├── fastapi/
│       │   └── express/
│       └── scripts/
│           ├── validate_env.py
│           └── check_migrations.py
├── tests/
│   ├── test_skill_structure.py
│   └── scenarios/
│       ├── authentication.md
│       ├── authorization.md
│       └── caching.md
└── docs/
    ├── installation.md
    └── roadmap.md
```

Do not assume every listed directory or file exists in the current version.

## Getting started

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd backend-engineering-skill
```

Replace `<YOUR_REPOSITORY_URL>` with the repository's actual Git URL.

### 2. Install the skill for your coding agent

The project is intended to maintain one canonical skill source and provide agent-specific installation instructions.

Common project-level skill locations include:

- **Codex:** `.agents/skills/backend-engineering/SKILL.md`
- **OpenCode:** `.agents/skills/backend-engineering/SKILL.md`
- **Claude Code:** `.claude/skills/backend-engineering/SKILL.md`

Discovery behavior and supported configuration can vary by agent version. Confirm the current official documentation for your installed version before relying on a path. Until an installer is provided, copy the canonical skill directory into the appropriate project-level location and verify that your agent discovers it.

### 3. Use the skill

After installation, ask your coding agent to perform a backend task that falls within the skill's description. For example:

```text
Inspect this backend project and use the Backend Engineering skill
to plan and implement authentication for the existing API.

Follow the current project conventions. Add appropriate tests,
run the relevant checks, and report any failures or unresolved risks.
Do not introduce new infrastructure unless it is justified.
```

The prompt is an example; actual behavior depends on the skill version, agent, model, and available tools.

## Recommended initial stack

The first implementation is intended to focus on one stack to keep the guidance testable:

- **Language:** Python
- **API framework:** FastAPI
- **Database:** PostgreSQL
- **ORM:** SQLAlchemy
- **Testing:** pytest

Redis, background-worker systems, load-testing tools, and additional frameworks can be introduced when their corresponding workflows are implemented and evaluated. The skill should not force these technologies onto projects that do not need them.

## Evaluation strategy

The project should be evaluated by the quality of the code agents produce—not by the length of its documentation.

Planned evaluation scenarios include:

| Scenario | What to verify |
|---|---|
| Authentication | Valid and invalid credentials are handled correctly |
| Authorization | Users cannot access another user's private resources |
| Database migration | Schema changes preserve data and constraints |
| Background jobs | Retry behavior and duplicate execution are handled safely |
| Caching | Invalidation and user/data isolation behave as intended |
| Rate limiting | Requests over configured limits are handled correctly |
| Performance | Results are measured against a documented workload and baseline |

Where practical, compare agent performance with and without the skill using the same task, repository, test suite, and evaluation criteria. Record differences in correctness, security, regressions, token usage, tool calls, and iteration count. Results should account for differences between agents and models.

## Security and responsible testing

- Use maintained libraries for security-sensitive functionality.
- Never commit real credentials, tokens, private keys, or production data.
- Do not run load or security tests against systems without authorization.
- Use explicit concurrency limits and request budgets for load tests.
- Review database migrations and destructive operations before execution.
- Treat generated code as a proposal that must be reviewed and tested.
- Do not claim checks passed unless they were actually executed and succeeded.

This skill provides engineering guidance; it does not guarantee that generated code is secure or production-ready.

## Development roadmap

1. Create the initial skill and define its scope.
2. Add core backend workflow and Python/FastAPI guidance.
3. Add authentication and authorization references with test scenarios.
4. Add database and migration guidance.
5. Add background-worker and caching workflows.
6. Add repeatable performance and load-testing scenarios.
7. Test skill discovery and behavior across Codex, Claude Code, and OpenCode.
8. Document installation, publish versioned releases, and improve the evaluation suite.

See [`docs/roadmap.md`](docs/roadmap.md) if that file exists in your checkout; otherwise, use this list as the initial roadmap.

## Contributing

Contributions are welcome as the project takes shape.

When proposing a new capability:

1. Explain the engineering problem it addresses.
2. Document when the approach is appropriate—and when it is not.
3. Include relevant security, failure, and edge cases.
4. Add a reproducible test scenario or validation procedure.
5. Identify assumptions, dependencies, and limitations.
6. Update the documentation to match the implemented behavior.

Keep guidance actionable, framework-version-aware, and supported by tests or authoritative documentation where possible.

## License

No license has been selected in this initial README. Add a `LICENSE` file before distributing the project, and choose a license that matches your intended reuse and contribution model.

## Project status

This README describes the intended direction of Backend Engineering Skill. Update the capability table, repository structure, installation steps, and roadmap as features are implemented and verified.
