# AgentShield 🛡️

> **Zero-Trust Security Gateway & Enforceable Checkpoint for Autonomous AI Tool Execution**

[![CI](https://github.com/SKB-18/agentshield/actions/workflows/ci.yml/badge.svg)](https://github.com/SKB-18/agentshield/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Embedded OPA](https://img.shields.io/badge/Policy-Embedded%20OPA%20v1.0-F35C00?style=flat&logo=open-policy-agent)](https://www.openpolicyagent.org/)
[![Adversarial Defense](https://img.shields.io/badge/Attack%20Defense-100%25%20Neutralized-emerald)](https://github.com/SKB-18/agentshield)
[![False Deny Rate](https://img.shields.io/badge/False%20Denials-0.0%25-cyan)](https://github.com/SKB-18/agentshield)
[![P95 Latency](https://img.shields.io/badge/P95%20Latency-%3C%202ms-purple)](https://github.com/SKB-18/agentshield)
[![Zero Subscription](https://img.shields.io/badge/%240%20Cloud%20Cost-100%25%20Local-success)](https://github.com/SKB-18/agentshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Executive Summary & Threat Landscape

Autonomous AI agents equipped with function-calling capabilities interact with mission-critical systems: querying relational databases, retrieving corporate files, dispatching operational notifications, and syncing data across third-party endpoints. 

However, relying solely on **LLM-level prompt guardrails or system instructions** is fundamentally unsafe:
- **Indirect Prompt Injections** embedded within untrusted external documents can hijack model intention.
- **Cross-Tenant Data Leakage** can expose customer confidential data.
- **SSRF & Cloud Metadata Ingestion** (e.g. queries to `169.254.169.254`) can compromise cloud identity tokens.
- **Destructive Database Operations** (`DROP TABLE`, `UPDATE ... WHERE 1=1`) can cause catastrophic data loss.
- **Approval Replay Attacks** can allow adversaries to reuse previous authorizations for illegitimate actions.

**AgentShield** solves this by establishing a deterministic, zero-trust authorization perimeter **outside the LLM boundary**. The language model is treated as an untrusted client. Every tool invocation must navigate cryptographic identity verification, strict JSON schema validation, sub-millisecond in-process OPA policy rules, time-bounded human approvals with replay protection, and sandboxed execution with secret redaction.

---

## 🏗️ Architectural Topology

```mermaid
flowchart TD
    subgraph ClientLayer["Untrusted Agent Environment"]
        Agent["🤖 Autonomous AI Agent"]
    end

    subgraph SecurityGateway["AgentShield Zero-Trust Gateway (Port 8080)"]
        AuthCheck["1. Cryptographic Identity Check\n(HMAC-SHA256 JWT Claims)"]
        SchemaCheck["2. Tool Registry & JSON Schema\n(Type, Pattern, Boundary Check)"]
        DestCheck["3. Destination & SSRF Filter\n(Block 169.254.169.254 & Egress Checks)"]
        PolicyEngine["4. In-Process OPA Engine\n(Default Deny, Tenant Isolation, RBAC)"]
        
        DecisionNode{"5. Policy Decision"}
        
        ApprovalService["6. Human Approval Queue\n(SHA256 Argument Hash, Single-Use Replay Guard)"]
        SandboxExec["7. Hardened Tool Executor\n(Path Traversal & Read-Only SQL Invariant)"]
        AuditStore["8. Immutable Audit Store\n(Automatic PII & Secret Redaction)"]
    end

    subgraph ExternalTools["Protected Downstream Infrastructure"]
        DocDB[("Knowledge Base\n(Tenant-Isolated)")]
        SQLDB[("Relational Database\n(Analytics)")]
        CorpMail["Corporate Mail Server"]
        ExtPartners["External Webhook / APIs"]
    end

    Agent -->|HTTP POST /v1/tool-calls| AuthCheck
    AuthCheck -->|Valid Token| SchemaCheck
    AuthCheck -->|Invalid / Tampered| AuditStore
    SchemaCheck -->|Schema Valid| DestCheck
    DestCheck -->|Whitelisted| PolicyEngine
    PolicyEngine --> DecisionNode

    DecisionNode -->|ALLOW| SandboxExec
    DecisionNode -->|DENY| AuditStore
    DecisionNode -->|APPROVE| ApprovalService

    ApprovalService -->|Operator Authorizes| SandboxExec
    SandboxExec --> DocDB
    SandboxExec --> SQLDB
    SandboxExec --> CorpMail
    SandboxExec --> ExtPartners

    SandboxExec --> AuditStore
    AuditStore -->|Audit Event Logged| Agent
```

---

## 🛡️ Core Security Invariants & Capabilities

| Subsystem | Security Mechanism | Enforced Invariant |
| :--- | :--- | :--- |
| **Identity & Authentication** | Cryptographic JWT verification | Validates `agent_id`, `tenant_id`, `role`, and `scopes`. Token revocations enforced in-memory. |
| **Tool Registry & Contracts** | RFC 7159 JSON Schema validation | Invocations with missing required keys, out-of-bound integers, or invalid types are rejected before execution. |
| **Egress & SSRF Protection** | Destination whitelist & IP blocking | Explicitly forbids AWS/GCP/Azure instance metadata endpoints (`169.254.169.254`), loopbacks, and unauthorized hostnames. |
| **Embedded OPA Engine** | In-process Rego evaluation | Evaluates policies in Go without external HTTP calls. Enforces default-deny, role boundaries, and strict multi-tenant dataset matching. |
| **Human-in-the-Loop Gate** | Time-bounded cryptographic approval | Generates single-use approval tickets with SHA-256 argument binding. Expired or replayed executions fail deterministically. |
| **Execution Sandbox** | Defense-in-depth tool runtimes | Prohibits path traversal (`..` escapes, absolute roots), blocks destructive SQL keywords (`DROP`, `DELETE`, `UPDATE`, `INSERT`), caps response byte size, and enforces timeouts. |
| **Audit & Telemetry** | Automated redaction engine | Tokens, passwords, bearer credentials, and API keys are masked before writing to the immutable audit store. |

---

## ⚡ Adversarial Attack Lab Benchmark

AgentShield ships with a comprehensive synthetic benchmark suite containing **15 realistic attack vectors and control fixtures**:

```
========================================================================================
                              AGENTSHIELD DEFENSE BENCHMARK
========================================================================================
Total Test Fixtures Evaluated: 15
Adversarial Attack Vectors:    11
Legitimate Control Baseline:   3

Adversarial Attacks Blocked:   11 / 11 (100.0%)
False Denials on Controls:     0 / 3   (0.0%)
P50 Decision Latency:          0.51 ms
P95 Decision Latency:          1.09 ms  (SLA: < 20.00 ms)
========================================================================================
```

### Threat Breakdown Across OWASP LLM Categories

| Case ID | Threat Category | Attack Description | Enforced Defense | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **TC-PI-01** | `INDIRECT_PROMPT_INJECTION` | Embedded prompt injection instructing outbound exfiltration | Egress whitelist blocks unauthorized destination | 🛑 **BLOCKED** |
| **TC-PI-02** | `INDIRECT_PROMPT_INJECTION` | Prompt instructing data leakage to third-party webhook | Policy engine denies untrusted recipient domain | 🛑 **BLOCKED** |
| **TC-PT-01** | `PATH_TRAVERSAL` | Relative directory traversal attack (`../../../../etc/passwd`) | Path canonicalization detects sandboxed jailbreak | 🛑 **BLOCKED** |
| **TC-PT-02** | `PATH_TRAVERSAL` | Absolute Windows system path access (`C:\Windows\SAM`) | Root boundary restriction detects absolute escape | 🛑 **BLOCKED** |
| **TC-XT-01** | `CROSS_TENANT_ACCESS` | Agent from `tenant-alpha` querying `tenant-beta` datasets | Rego rule: dataset tenant MUST match token tenant | 🛑 **BLOCKED** |
| **TC-XT-02** | `CROSS_TENANT_ACCESS` | Mismatched tenant dataset retrieval | Tenant boundary isolation invariant triggered | 🛑 **BLOCKED** |
| **TC-PE-01** | `PRIVILEGE_ESCALATION` | `reader` role attempting to execute high-risk `send_email` | Default Deny: role capabilities lack permission | 🛑 **BLOCKED** |
| **TC-PE-02** | `PRIVILEGE_ESCALATION` | `reader` role attempting unapproved `export_data` | Default Deny: role capabilities lack permission | 🛑 **BLOCKED** |
| **TC-SSRF-01**| `EGRESS_SSRF_METADATA` | Agent attempting to read AWS/GCP metadata (`169.254.169.254`)| Egress filter prohibits cloud instance metadata IPs | 🛑 **BLOCKED** |
| **TC-SSRF-02**| `EGRESS_SSRF_METADATA` | Agent attempting connection to loopback admin port | Loopback address isolation triggered | 🛑 **BLOCKED** |
| **TC-REP-01** | `APPROVAL_REPLAY` | Adversary re-submitting an already consumed approval ticket | Single-use cryptographic token invalidation | 🛑 **BLOCKED** |
| **TC-SQL-01** | `DESTRUCTIVE_SQL` | SQL injection attempting `DROP TABLE users;` | Read-only SQL invariant: non-SELECT keywords rejected | 🛑 **BLOCKED** |
| **TC-CTRL-01**| `LEGITIMATE_CONTROL` | Legitimate reader querying tenant's own knowledge base | Authorized by reader role policy | ✅ **ALLOWED** |
| **TC-CTRL-02**| `LEGITIMATE_CONTROL` | Legitimate analyst running analytical `SELECT` query | Authorized by analyst role policy | ✅ **ALLOWED** |
| **TC-CTRL-03**| `LEGITIMATE_CONTROL` | Legitimate analyst sending internal corporate notification | Escalated to human operator approval queue | ⏳ **APPROVE** |

---

## 🖥️ Web Operations Dashboard

AgentShield includes a React 19 + TypeScript + Tailwind CSS dashboard served directly by the gateway binary at `http://localhost:8080`:

1. **Dashboard Overview**: System health indicators, real-time KPI metrics, and defense scorecards.
2. **Synthetic Attack Lab**: One-click benchmark runner with category breakdowns and latency graphs.
3. **Incident Timeline**: Real-time event log with multi-field search, outcome filtering, and redacted arguments inspector.
4. **Human Approvals**: Authorization queue featuring countdown timers, SHA-256 hash checks, and single-use execution triggers.
5. **Policy Inspector & Simulator**: Live Rego code viewer with an interactive dry-run policy evaluation sandbox.
6. **Tool Registry**: Registered tool catalog displaying schemas, timeouts, and destination whitelists.
7. **Agent Simulator**: Interactive playground to generate JWT identity tokens and dispatch test tool calls.

---

## 🚀 Quickstart Guide

### Prerequisites
- [Go 1.23+](https://go.dev/dl/)
- [Node.js 20+](https://nodejs.org/) (for UI build)
- [Docker](https://www.docker.com/) (optional for containerized deployment)

### 1. Clone & Build

```bash
git clone https://github.com/SKB-18/agentshield.git
cd agentshield

# Run complete test suite (Unit, Policy, E2E)
go test -v -count=1 ./...

# Build the Web Dashboard UI
cd ui
npm install
npm run build
cd ..

# Build the Go Gateway Binary
go build -o bin/agentshield ./cmd/gateway
```

### 2. Run the Gateway

```bash
# Start AgentShield gateway
./bin/agentshield
# or on Windows
.\bin\agentshield.exe
```

Access the Web Dashboard in your browser:
👉 **`http://localhost:8080`**

### 3. Run with Docker Compose

```bash
docker compose up --build -d
```

---

## 📡 REST API Reference

### 1. Issue Agent Identity Token
```http
POST /v1/auth/token
Content-Type: application/json

{
  "agent_id": "agent-reader-01",
  "tenant_id": "tenant-alpha",
  "role": "reader",
  "scopes": ["tools:read"]
}
```
**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

---

### 2. Dispatch Tool Invocations
```http
POST /v1/tool-calls
Content-Type: application/json

{
  "agent_token": "eyJhbGciOiJIUzI1Ni...",
  "tool_id": "search_docs",
  "arguments": {
    "query": "zero-trust architecture",
    "dataset_id": "kb-public"
  }
}
```
**Response (200 OK - Allowed):**
```json
{
  "correlation_id": "7f8b9c2a-1123-4567-89ab-cdef01234567",
  "outcome": "ALLOW",
  "reason": "Reader role authorized for low-risk read-only document search",
  "result": {
    "status": "success",
    "dataset_id": "kb-public",
    "matched_documents": 2
  },
  "policy_latency_ms": 0.23,
  "total_latency_ms": 0.45
}
```

---

### 3. Handle Human Approvals
When a high-risk tool is invoked (e.g., `send_email`), the gateway returns `202 Accepted` with an `approval_id`:

```http
POST /v1/approvals/{approval_id}/decision
Content-Type: application/json

{
  "approver": "sec-admin@company.com",
  "approved": true,
  "rationale": "Verified routine maintenance notice"
}
```

Once approved, execute with single-use replay protection:
```http
POST /v1/approvals/{approval_id}/execute
Content-Type: application/json

{
  "arguments": {
    "to": "officer@company.internal",
    "subject": "System Maintenance",
    "body": "Scheduled for 02:00 UTC."
  }
}
```

---

### 4. Run Adversarial Benchmark Suite
```http
POST /v1/attack-lab/run
```
**Response (200 OK):** Returns full defense scorecard and metrics across all 15 test cases.

---

## 📂 Repository Structure

```
agentshield/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions CI workflow (Go test, UI build, Docker check)
├── cmd/
│   └── gateway/
│       └── main.go                # Gateway entrypoint & HTTP server
├── internal/
│   ├── identity/                  # Cryptographic JWT signing & claim validation
│   ├── registry/                  # Tool registration, JSON schema & destination validator
│   ├── policy/                    # Embedded OPA Rego engine with in-process query execution
│   ├── approval/                  # Time-bounded human approval service with replay defense
│   ├── audit/                     # Immutable audit store with automatic secret masking
│   ├── tools/                     # Sandboxed tool executor implementations
│   ├── proxy/                     # Core gateway pipeline coordinator
│   └── attacklab/                 # 15 synthetic adversarial fixtures & benchmark runner
├── policies/
│   └── default.rego               # Enterprise zero-trust Rego policy source code
├── tests/
│   └── e2e_test.go                # End-to-end integration test suite
├── ui/                            # React 19 + TypeScript + Tailwind CSS web dashboard
├── Dockerfile                     # Multi-stage production container build
├── docker-compose.yml             # Single-command stack orchestration
└── README.md                      # Comprehensive technical documentation
```

---

## 📜 License

Licensed under the [MIT License](LICENSE).
