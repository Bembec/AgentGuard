# AgentGuard

AgentGuard is an AI-agent permission and security control plane written in Python.

It evaluates actions requested by multiple agents, applies `ALLOW`, `ASK`, or `BLOCK` policies, tracks risk independently for every agent, requests human approval for sensitive actions, suspends unsafe agents, and stores audit evidence.

>>**Core security principle:**Agent identity is not the same as agent permission.
> An agent must eventually prove its identity before AgentGuard evaluates what that identity is allowed to do.

## Current Version

**Version 8 â€” FastAPI Multi-Agent Control Plane**

AgentGuard can now be used through:

- An interactive Python terminal
- A FastAPI REST API
- Interactive OpenAPI documentation
- Per-agent audit and summary endpoints

## Core Features

- Multi-agent registration and independent state
- `ALLOW`, `ASK`, and `BLOCK` policy decisions
- Weighted risk scoring
- `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` risk levels
- Human approval and denial workflows
- Automatic agent suspension
- Refusal of actions from suspended agents
- Administrator-controlled reset
- JSON state persistence
- SQLite audit history
- Text security logging
- FastAPI control-plane endpoints
- Unknown-agent rejection
- Input validation
- Environment-variable administrator PIN

## Project Structure

```text
AgentGuard/
â”œâ”€â”€ api.py
â”œâ”€â”€ database.py
â”œâ”€â”€ main.py
â”œâ”€â”€ requirements.txt
â”œâ”€â”€ README.md
â””â”€â”€ .gitignore
```

Runtime files are generated locally and excluded from Git:

```text
agent_state.json
agentguard.db
security.log
__pycache__/
```

## Permission Policy

The current demonstration policy includes:

| Action | Decision | Risk |
|---|---|---:|
| `read_file` | `ALLOW` | 0 |
| `search_logs` | `ALLOW` | 0 |
| `delete_file` | `ASK` | 20 |
| `run_program` | `ASK` | 25 |
| `send_email` | `BLOCK` | 40 |
| Unknown action | `BLOCK` | Defined by the engine |

Sensitive `ASK` actions require an explicit `APPROVED` or `DENIED` decision.

Blocked actions increase both the agentâ€™s risk score and blocked-attempt count.

## Risk Levels

| Score | Risk level |
|---:|---|
| 0â€“29 | `LOW` |
| 30â€“59 | `MEDIUM` |
| 60â€“99 | `HIGH` |
| 100 or higher | `CRITICAL` |

An agent is suspended when it reaches the configured risk threshold or maximum blocked-attempt count.

Every registered agent has its own:

- Status
- Risk score
- Risk level
- Blocked-attempt count
- Audit history

## Installation

Install the V8 dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Terminal Mode

Run AgentGuard directly:

```powershell
python main.py
```

Terminal commands include:

```text
list_agents
switch_agent
reset
quit
```

You can also enter supported actions such as:

```text
read_file
search_logs
delete_file
run_program
send_email
```

## FastAPI Mode

Set an administrator PIN for the current PowerShell session:

```powershell
$env:AGENTGUARD_ADMIN_PIN = "2468"
```

Start the API:

```powershell
python -m uvicorn api:app --reload
```

Open the interactive documentation:

```text
http://127.0.0.1:8000/docs
```

The API root is:

```text
http://127.0.0.1:8000
```

Stop the server with `Ctrl + C`.

Do not use the example PIN in a real deployment.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Application information |
| `GET` | `/health` | API health and agent count |
| `GET` | `/permissions` | Policy and risk configuration |
| `GET` | `/agents` | List registered agents |
| `POST` | `/agents` | Register an agent |
| `GET` | `/agents/{agent_name}` | Get one agentâ€™s state |
| `POST` | `/actions/evaluate` | Evaluate an agent action |
| `GET` | `/agents/{agent_name}/audit` | Get recent audit events |
| `GET` | `/agents/{agent_name}/summary` | Get audit statistics |
| `POST` | `/agents/{agent_name}/reset` | Administratively reset an agent |

## Example Action Evaluation

Request:

```json
{
  "agent_name": "research_agent",
  "action": "read_file"
}
```

Example response:

```json
{
  "agent_name": "research_agent",
  "action": "read_file",
  "policy_decision": "ALLOW",
  "approval": "NOT_REQUIRED",
  "risk_added": 0,
  "risk_score": 0,
  "risk_level": "LOW",
  "blocked_attempts": 0,
  "agent_status": "ACTIVE",
  "message": "Action allowed by policy."
}
```

## Human Approval Example

Approved request:

```json
{
  "agent_name": "approval_test_agent",
  "action": "delete_file",
  "approval": "APPROVED"
}
```

Denied request:

```json
{
  "agent_name": "denied_test_agent",
  "action": "delete_file",
  "approval": "DENIED"
}
```

If no approval is supplied for an `ASK` action, AgentGuard returns `PENDING`.

## Automatic Suspension

A blocked action such as `send_email` adds risk and increases the blocked-attempt count.

Example progression:

```text
Attempt 1: Risk 40, blocked attempts 1, ACTIVE
Attempt 2: Risk 80, blocked attempts 2, ACTIVE
Attempt 3: Risk 120, blocked attempts 3, SUSPENDED
```

Once suspended, the agent cannot perform normally permitted actions until an authorized administrator resets it.

## Administrator Reset

The reset endpoint requires the `X-Admin-Pin` request header.

In the interactive API documentation:

1. Open `POST /agents/{agent_name}/reset`.
2. Enter the agent name.
3. Enter the configured PIN in `x-admin-pin`.
4. Execute the request.

A successful reset returns the agent to:

```text
Status: ACTIVE
Risk score: 0
Blocked attempts: 0
```

The reset is recorded in the audit trail.

## Audit Records

AgentGuard stores security events in SQLite and writes local text events to `security.log`.

Audit information includes:

- Agent name
- Timestamp
- Requested action
- Policy decision
- Approval result
- Risk score
- Risk level
- Agent status

Runtime logs and databases are excluded from Git because real security records may contain sensitive information.

## Version History

### Version 1 â€” Basic Permission Policy

- Added `ALLOW`, `ASK`, and `BLOCK` decisions
- Added terminal action evaluation

### Version 2 â€” Block Tracking

- Counted blocked attempts
- Added automatic suspension

### Version 3 â€” Risk Scoring

- Added action risk weights
- Added risk levels and thresholds

### Version 4 â€” Human Approval

- Added approval for sensitive actions
- Added approved and denied outcomes

### Version 5 â€” Administrative Reset

- Added PIN-protected reset
- Added persistent state and security logging

### Version 6 â€” SQLite Audit History

- Added database-backed security events
- Added recent-event and summary queries

### Version 7 â€” Multi-Agent Control

- Added independent agent states
- Added agent registration and switching
- Preserved state independently for every agent

### Version 8 â€” FastAPI Control Plane

- Added REST API access
- Added interactive API documentation
- Added agent registration and state endpoints
- Added remote policy evaluation
- Added approval input
- Added audit and summary endpoints
- Added administrator reset endpoint
- Verified allow, block, approval, denial, suspension, refusal, reset, and audit workflows

## Current Security Limitation

V8 identifies an agent using the `agent_name` supplied in the request.

The API does not yet cryptographically authenticate that the caller truly owns that agent identity. Therefore, V8 is suitable as a local learning and development control plane, not as a production authorization system.

## Planned Security Architecture

The next security layer will enforce:

```text
Agent credential
â†’ Identity authentication
â†’ Scope boundary
â†’ Permission decision
â†’ Risk update
â†’ Audit evidence
```

Planned improvements include:

- Agent API keys or signed credentials
- Hashed credential storage
- Credential rotation and revocation
- Agent-specific permission scopes
- Resource and tool boundaries
- Per-agent rate limits
- Authenticated human approvers
- Policy administration endpoints
- Real-time security alerts
- Web monitoring dashboard
- Sandboxed tool execution
- AgentGuard adapter for CanaryLab AI

## Future Principle

```text
Agent identity â‰  agent permission
```

Authentication will answer:

```text
Who is making this request?
```

Authorization will separately answer:

```text
What is this authenticated agent permitted to do?
```

This separation is essential for building a secure multi-agent control plane.

## Safety Notice

AgentGuard is a defensive educational project. It currently evaluates and records simulated agent actions. It does not provide unrestricted command execution, filesystem access, browser access, or network access.

## Author

Michael Chukwujekwu Alughere
