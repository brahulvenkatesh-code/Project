# AI Risk Governance System - Architecture Design

This architecture follows a **Zero Trust** security model with **Strict Component Isolation**.

```mermaid
graph TD
    subgraph "External World"
        User[Authenticated User]
        Auditor[Auditor Role]
    end

    subgraph "API Gateway (Security Layer)"
        WAF[WAF / Input Guard]
        Auth[JWT Auth RBAC/ABAC]
        RateLimit[Rate Limiter]
    end

    subgraph "Decision Zone (Deterministic)"
        RE[Deterministic Risk Engine]
        Rules[(Versioned Rules)]
        Snap[Decision Snapshots - JSON Stores]
    end

    subgraph "Audit Zone (Tamper-Proof)"
        Logs[Append-only File Logs / Stdout]
    end

    subgraph "Explanation Zone (NanoBot)"
        NB[NanoBot LLM Service]
        PromptGuard[Prompt Injection / Output Filter]
    end

    User --> WAF
    Auditor --> WAF
    WAF --> Auth
    Auth --> RateLimit
    RateLimit --> RE
    RE --> Rules
    RE --> Snap
    RE --> Logs

    %% Strict Read-Only Bridge
    RE -.-> NB_Bridge[Read-Only Snapshot Bridge]
    NB_Bridge --> NB
    NB --> PromptGuard
    PromptGuard --> User

    %% Cross-Component Isolation
    NB -X- RE
    NB -X- Rules
    NB -X- Logs
```

## Component Breakdown

1.  **API Gateway**:
    *   **WAF**: Strips malicious payloads, checks blocklists, and enforces JSON schema.
    *   **Auth**: Validates JWTs, enforces RBAC (Admin/Auditor/User) and ABAC (Ownership).
    *   **Rate Limiter**: Prevents brute-force and DoS attacks.

2.  **Deterministic Risk Engine**:
    *   **Input**: Sanitized metrics.
    *   **Process**: Fixed math (no LLM). Rules are hardcoded constants (v1, v2, etc.).
    *   **Output**: Signed decision snapshot + Machine-readable rule trace.
    *   **Audit**: Every decision is logged with a unique UUID to the `Audit Zone`.

3.  **NanoBot (LLM)**:
    *   **Constraint**: Read-only. Cannot modify decision state.
    *   **Data Source**: Only receives the *results* of the Risk Engine via a one-way bridge.
    *   **Safety**: Prompt injection protection (WAF) and output filtering to prevent score hallucinations.

4.  **Audit Zone**:
    *   **Storage**: Encrypted-at-rest local file storage or secure logging service.
    *   **Logging**: High-integrity logs tracking `Who`, `What`, `When`, and `Why`.
