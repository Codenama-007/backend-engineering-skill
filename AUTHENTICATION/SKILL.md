# Authentication — Backend Engineering Skill

**Capability Level:** L2 — Moderate  
**Category:** Backend Security  
**Purpose:** Help AI coding agents implement and verify standard authentication while minimizing unnecessary model costs.

> **Status:** Initial specification. This README defines the scope and model-selection policy before the `SKILL.md` and reference implementations are written.

## 1. Objective

Provide a repeatable workflow for implementing standard authentication in an existing backend.

The agent should inspect the project, follow its current framework and conventions, use maintained security libraries, implement the required authentication flow, add tests, and report the checks it actually ran.

The goal is **cost-aware engineering, not cost cutting at the expense of security**.

Use the least expensive model that can reliably complete the task while keeping security requirements and verification standards fixed.

## 2. Authentication Complexity Levels

Authentication tasks are classified by implementation complexity. Security impact is assessed separately.

| Level | Classification | Typical Tasks | Default Model Strategy |
|---|---|---|---|
| L1 | Basic | Input validation, straightforward authentication bug fixes, existing password verification | Use a cheaper model when requirements are clear. |
| L2 | Moderate | Registration, login, password hashing, JWT access tokens, protected routes | Start with a cheaper model and escalate if necessary. |
| L3 | Advanced | Refresh-token rotation, complex session management, OAuth/OIDC integrations, advanced RBAC | Use a stronger model when design or security analysis is nontrivial. |
| L4 | Critical | High-impact identity migrations, complex distributed identity systems, security incident remediation | Prefer a stronger model, independent review, and rigorous security testing. |

These levels are project-specific classifications, not universal security standards.

### Complexity vs. Security Risk

The agent must assess two independent dimensions:

- **Complexity:** How difficult is the design and implementation?
- **Security impact:** What could happen if the implementation is incorrect?

A standard login endpoint might be L2 in complexity but high in security impact.

A cheaper model may implement it, but it must not skip security checks, tests, or review.

## 3. L2 Scope — Standard Authentication

The default L2 implementation may include the following features, depending on project requirements.

### Core Features

- User registration with server-side input validation.
- Password hashing and verification using a maintained security library.
- Login and logout behavior appropriate to the chosen authentication architecture.
- JWT access-token generation and validation when JWT is the selected approach.
- Protected API routes using middleware, dependencies, or guards.
- Environment-based configuration for secrets.
- Consistent handling of invalid credentials and malformed requests.
- Appropriate handling of missing, invalid, and expired tokens.
- Unit and integration tests.
- Documentation of configuration and setup requirements.

### Engineering Requirements

The agent must:

1. Inspect the existing backend before making changes.
2. Identify the language, framework, installed versions, and dependencies.
3. Follow existing architectural conventions.
4. Avoid introducing unnecessary infrastructure.
5. Use established security libraries rather than inventing cryptographic mechanisms.
6. Add tests for both successful and unsuccessful authentication.
7. Run the relevant tests and report the actual results.
8. Document assumptions and unresolved security concerns.

**Important:** Do not force JWT into a project that already uses secure server-side sessions. Choose an approach that fits the requirements and existing architecture.

## 4. Features Outside the Default L2 Scope

The following features require a separate complexity assessment:

- Refresh-token rotation and reuse detection.
- Password-reset and account-recovery workflows.
- Email or phone verification.
- OAuth 2.0 and OpenID Connect integrations.
- Multi-factor authentication.
- Complex role-based or attribute-based access control.
- Multi-tenant identity isolation.
- Migration from an existing identity provider.
- Complex session revocation and identity lifecycle management.

These features are not automatically impossible for cheaper models.

However, they may introduce additional architectural decisions, security requirements, and failure scenarios.

The agent must reassess the task before proceeding.

## 5. Cost-Aware Model Selection

### Default Policy

For an L2 authentication task:

1. Inspect the repository and understand the requirements.
2. Identify the existing authentication architecture.
3. Check the installed framework and dependency versions.
4. Identify security-sensitive decisions and acceptance criteria.
5. Determine whether the task matches a documented implementation pattern.
6. Recommend a cheaper model when the task is sufficiently specified and straightforward.
7. Implement the feature using the relevant references.
8. Run the required tests and validation checks.
9. Escalate if uncertainty, implementation failures, or security concerns persist.
10. Report the results honestly.

### When to Escalate

Recommend switching to a stronger model or requesting additional review when:

- The existing authentication architecture is unclear.
- The task changes token lifecycles or session invalidation.
- A possible authentication bypass is discovered.
- Cross-user access or identity isolation may be broken.
- Tests repeatedly fail and the cause remains unclear.
- Requirements conflict or important assumptions cannot be verified.
- A migration could cause account lockout or data exposure.
- The agent proposes weakening security checks to make tests pass.

### Model Switching Limitations

An Agent Skill can provide model-selection recommendations and escalation instructions, but it cannot guarantee automatic model switching across Codex, Claude Code, and OpenCode.

Model selection and switching capabilities depend on the host agent, its configuration, and its version.

Therefore, the skill must:

- Use the host agent's supported model-selection mechanism when available.
- Ask the user or operator to switch models when automatic switching is unavailable.
- Never claim that a model was changed without confirmation.
- Apply the same security requirements and acceptance tests regardless of model choice.

**The objective is to reduce unnecessary reasoning costs without reducing implementation quality.**

## 6. Required Validation

For L2 authentication tasks, select tests appropriate to the implementation.

At minimum, consider the following scenarios.

| Test | Expected Result |
|---|---|
| Register with valid input | Registration succeeds. |
| Register with invalid input | The request is rejected appropriately. |
| Inspect stored passwords | Passwords are not stored in plaintext. |
| Login with valid credentials | Authentication succeeds. |
| Login with invalid credentials | Authentication fails safely. |
| Access a protected route without credentials | Access is rejected. |
| Submit a malformed token | The token is rejected. |
| Submit an expired token | The token is rejected when token authentication is used. |
| Inspect error responses | Responses do not expose secrets or unnecessary sensitive information. |
| Run existing tests | Existing functionality continues to work. |

If authorization or resource ownership is included in the task, add tests verifying that one user cannot access another user's private resources.

Authentication establishes identity; authorization determines what that identity is allowed to access.

Tests are necessary, but passing tests alone does not prove that an authentication implementation is secure.

## 7. Reference Implementations

The planned folder structure is:

```text
Authentication/
├── README.md
├── SKILL.md
├── app.py
├── app.js
├── app.ts
├── levels/
│   ├── L1-basic.md
│   ├── L2-moderate.md
│   ├── L3-advanced.md
│   └── L4-critical.md
├── references/
│   ├── security.md
│   └── testing.md
└── tests/
    ├── test_authentication.md
    └── test_authorization.md
```

This is a proposed structure. The additional files should be introduced as they are implemented.

### Reference File Responsibilities

**`app.py`**
- Python authentication reference.
- Initially targets FastAPI.
- Demonstrates the selected L2 authentication flow.

**`app.js`**
- JavaScript authentication reference.
- Demonstrates an appropriate implementation for the selected JavaScript framework.

**`app.ts`**
- TypeScript authentication reference.
- Demonstrates typed request handling and authentication logic.

Each implementation should document its framework, dependency assumptions, required environment variables, setup instructions, and limitations.

The examples should demonstrate equivalent security principles without pretending that the implementations are interchangeable across frameworks.

These files are educational references, not drop-in production authentication systems.

## 8. Definition of Done

An L2 authentication task is complete only when:

- The implementation satisfies the requirements.
- The implementation follows the existing project architecture.
- Security-sensitive decisions are documented.
- Relevant success and failure tests are included.
- Available tests and checks have actually been executed.
- Failed checks are reported honestly.
- Existing functionality has not been knowingly broken.
- No security controls have been disabled merely to pass tests.
- Remaining risks and limitations are documented.

### Required Final Report

The coding agent should summarize:

1. What changed.
2. Which files were modified.
3. Important architectural decisions.
4. Security considerations.
5. Tests executed and their actual results.
6. Any remaining risks or limitations.
7. Whether model escalation was recommended and why.

## 9. Evaluation Strategy

The skill should be evaluated by the quality of the code agents produce, not by the length of its documentation.

Create a repeatable test repository and compare results with and without the skill.

Measure:

- Correctness.
- Security-test results.
- Regression rate.
- Number of tool calls.
- Token consumption, where measurable.
- Number of implementation iterations.
- Whether the final result satisfies acceptance criteria.

Use the same task, repository, and evaluation criteria wherever practical.

Account for differences between coding agents and models when interpreting results.

A cheaper model is useful only when it can complete the task reliably enough for the intended use case.

## 10. Security and Responsible Testing

- Use maintained libraries for security-sensitive functionality.
- Never commit real credentials, access tokens, or private keys.
- Do not expose secrets in logs or error responses.
- Review authentication and authorization boundaries carefully.
- Do not run security or load tests against systems without authorization.
- Review potentially destructive migrations before execution.
- Treat generated code as a proposal that must be tested and reviewed.
- Never claim that a test passed unless it was executed successfully.

This skill provides engineering guidance; it does not guarantee that generated code is secure or production-ready.

## 11. Development Roadmap

1. Finalize the L1–L4 complexity definitions.
2. Create `SKILL.md` with task classification, implementation workflow, and escalation rules.
3. Add the L2 Python reference implementation.
4. Add equivalent JavaScript and TypeScript references.
5. Create authentication and authorization evaluation scenarios.
6. Verify skill discovery in Codex, Claude Code, and OpenCode.
7. Test model-selection recommendations and measure token consumption.
8. Expand into advanced authentication features only after the L2 workflow is reliable.

## 12. Guiding Principle

**Use the least expensive model that can reliably complete the task, but never lower the security or verification standard to save tokens.**

The skill should help coding agents make better engineering decisions, not merely generate code faster.