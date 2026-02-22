# AI Execution Boundary Standard (AEBS)

**Version:** 1.0
**Status:** Reference Specification

**AEBS is a structural contract specification.**
**It is not a product, library, or enforcement kernel.**

---

## 1. Purpose

Define a structural contract for safe command execution in AI-mediated systems.

AEBS separates:

* Decision
* Authority
* Execution

---

## 2. Terminology

**Execution Proposal** — Raw command string
**Verdict** — ALLOW / HOLD / STOP
**Execution Contract** — Authority object permitting execution
**Boundary** — Pre-execution decision layer

---

## 3. Core Invariants

1. Execution must not occur without prior evaluation.
2. Default verdict must be DENY.
3. Evaluation must occur before runtime invocation.
4. There must be exactly one execution call site.

---

## 4. Conformance Levels

### Level 1 — Structural Boundary

* Pre-execution evaluation
* Default deny
* Single execution path

### Level 2 — Authority Binding

* Execution requires explicit authority object

### Level 3 — Replay Resistance

* Deterministic binding of proposal identity

### Level 4 — Environment Binding

* Authority tied to execution context identity

### Level 5 — Enforcement Depth

* Multi-step verification
* Fail-closed semantics

---

## 5. Non-Goals

AEBS does not define:

* Shell parsing semantics
* Intent classification
* Sandbox mechanisms
* Runtime containment systems

---

## 6. Relationship to Other Controls

| Mechanism          | Role                          |
| ------------------ | ----------------------------- |
| Sandbox            | Damage containment            |
| Semantic Guardrail | Intent inference              |
| AEBS               | Structural execution contract |

They operate at different layers.

---

## 7. Threat Model (Minimal)

AEBS addresses:

* Implicit execution
* AI-generated unsafe commands
* Partial-control CI environments

AEBS does not address:

* Kernel compromise
* Host-level escape
* Post-execution damage

---

## 8. Reference Implementation

Level 1 reference: `execution-guard-action`

Higher enforcement levels are not defined in this document.

---

## 9. Design Constraints

### 9.1 No Shell Semantics Interpretation

AEBS evaluates command identity at the boundary layer.

It does **not**:

* Parse shell syntax
* Expand globs
* Resolve environment variables
* Decompose pipelines

### 9.2 Deterministic Evaluation

Decision must be deterministic for identical inputs.

No probabilistic models.
No LLM-based judgment at the boundary.

### 9.3 Fail-Closed Default

Missing policy → DENY
Unknown command → DENY
Evaluation failure → DENY

---

## 10. Authority Token Contract

Authority tokens bind:

* Proposal identity (hash)
* Policy state (hash)
* Execution environment (fingerprint)
* Temporal validity (TTL)
* Cryptographic proof (signature)

Token must be verified before execution.

---

## 11. Execution Flow

```
Proposal → Evaluate → Verdict
                ↓
           ALLOW → Issue Authority Token
                ↓
           Verify Token → Execute
```

Execution call site is reached only after verification passes.

---

## 12. Conformance Declaration

Implementations may declare conformance level.

Example:

```
AEBS Level 1 — Structural Boundary
```

Conformance requires:

* Default DENY
* Pre-execution evaluation
* Single execution call site

---

## 13. Versioning

This specification uses semantic versioning.

Current version: **1.0**

---

## 14. License

This specification is released under CC0 1.0 Universal (Public Domain).

Implementations may use any license.

---

## 15. Reference

Reference implementation: [execution-guard-action](https://github.com/Nick-heo-eg/execution-guard-action)

---

**End of Specification**
