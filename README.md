# AgentGuard

AgentGuard is a Python-based AI agent permission and security monitor. It sits between an AI agent and the actions it wants to perform, checks each action against a security policy, and records the resulting decision.

The long-term goal is to combine AI-agent observability, permission control, audit logging, risk scoring and human approval in one platform.

## Permission Decisions

AgentGuard currently supports three policy decisions:

* `ALLOW` — the agent can perform the action.
* `ASK` — human approval is required before the action proceeds.
* `BLOCK` — the action is forbidden.

Actions not found in the permission policy are blocked by default.

## Version 1

Version 1 introduced the basic permission-monitoring system.

### Features

* Accepts an action from the terminal
* Checks the action against a permission dictionary
* Returns `ALLOW`, `ASK` or `BLOCK`
* Blocks unknown actions by default
* Records actions and decisions in `security.log`

## Version 2

Version 2 introduces an emergency suspension system for repeatedly blocked actions.

### Features

* Keeps AgentGuard running for multiple actions
* Counts blocked actions during the session
* Suspends the agent after three blocked attempts
* Refuses every normal action while the agent is suspended
* Supports manual reset
* Resets the blocked-attempt counter after manual reset
* Records timestamps, decisions, agent status and blocked-attempt counts
* Supports a `quit` command for safely closing the session

## Version 3

Version 3 introduces weighted risk scoring. AgentGuard now evaluates the accumulated danger of an agent’s behaviour instead of relying only on the number of blocked actions.

### Features

* Assigns different risk points to different actions
* Gives unknown actions a high default risk value
* Accumulates risk throughout the session
* Classifies behaviour as `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`
* Records risk scores and levels in the audit log
* Suspends the agent when its score reaches the critical threshold
* Retains the three-block emergency suspension from Version 2
* Resets both the risk score and blocked-attempt counter after manual reset

### Current Risk Weights

| Action         | Decision | Risk points |
| -------------- | -------- | ----------: |
| `read_file`    | ALLOW    |           0 |
| `search_logs`  | ALLOW    |           0 |
| `delete_file`  | ASK      |          20 |
| `run_program`  | ASK      |          25 |
| `send_email`   | BLOCK    |          40 |
| Unknown action | BLOCK    |          50 |

### Risk Levels

|       Score | Risk level |
| ----------: | ---------- |
|        0–19 | LOW        |
|       20–59 | MEDIUM     |
|       60–99 | HIGH       |
| 100 or more | CRITICAL   |

AgentGuard suspends the agent when either the risk score reaches `100` or three blocked actions occur.

## Version 4

Version 4 introduces a human-in-the-loop approval workflow for sensitive actions classified as `ASK`.

### Features

* Pauses sensitive actions for human review
* Accepts `yes` or `y` as approval
* Accepts `no` or `n` as denial
* Rejects invalid approval responses and asks again
* Separately records the policy decision and human decision
* Uses `NOT_REQUIRED` for actions that do not need approval
* Continues calculating risk regardless of the approval result
* Records approval outcomes in the security audit log

AgentGuard currently simulates whether the requested action may proceed. It does not yet perform the actual file or program operation.


## Version 5

Version 5 protects the reset operation with administrator authentication and saves AgentGuard’s security state between program sessions.

### Features

* Reads the administrator PIN from an environment variable
* Keeps the PIN outside the source code and GitHub repository
* Hides PIN input using Python’s `getpass`
* Rejects unauthorized reset attempts
* Prevents unnecessary reset attempts while the agent is active
* Saves agent status, risk score and blocked-attempt count in JSON
* Restores the saved security state when AgentGuard starts
* Preserves suspension after the program is closed or restarted
* Saves authenticated reset results immediately
* Falls back to a safe default state if the state file is missing or invalid


## Version 6 — SQLite Audit Database

AgentGuard V6 introduces persistent database-backed security auditing.

### Features

* Automatically creates an SQLite database
* Stores every security decision as an audit event
* Records actions, decisions, approvals, risk scores, and agent status
* Keeps the existing text log as a backup
* Displays the five most recent events with `view_audit`
* Displays database statistics with `audit_summary`
* Preserves the agent’s security state between sessions

### Audit Commands

Use the following commands while AgentGuard is running:

* `view_audit` — displays the five most recent audit events
* `audit_summary` — displays total events, allowed actions, approval requests, blocked actions, refused actions, and the highest recorded risk score

### Main Project Files

* `main.py` — AgentGuard policy and security monitoring system
* `database.py` — SQLite database creation and audit queries
* `README.md` — project documentation
* `.gitignore` — prevents private runtime files from being uploaded

Runtime files such as `agentguard.db`, `agent_state.json`, and `security.log` are excluded from GitHub.


## Version 7 — Multi-Agent Security Monitoring

AgentGuard V7 can monitor multiple AI agents while maintaining an independent security state for each one.

### Features

* Registers multiple AI agents by name
* Maintains separate risk scores for every agent
* Maintains separate blocked-attempt counts
* Suspends dangerous agents individually
* Keeps safe agents active when another agent is suspended
* Stores each agent’s identity in the SQLite audit database
* Filters audit history and summaries by the active agent
* Converts the previous V6 state into a `legacy_agent` automatically
* Preserves all agent states between program sessions

### Agent Management Commands

* `list_agents` — displays all registered agents and their security states
* `switch_agent` — switches to an existing agent or registers a new agent
* `view_audit` — displays recent events for the active agent
* `audit_summary` — displays security statistics for the active agent
* `reset` — resets a suspended agent after administrator verification
* `quit` — saves all agent states and closes AgentGuard

### Multi-Agent Isolation

Each registered agent has its own:

* Status
* Risk score
* Risk level
* Blocked-attempt count
* Audit history
* Audit summary

A suspended agent cannot affect the security state of other registered agents.


### Configuring the Administrator PIN

PowerShell:

```powershell
$env:AGENTGUARD_ADMIN_PIN = "choose-a-private-pin"
python main.py
```

The environment variable is temporary and applies only to the current terminal session.

### Persistent State

AgentGuard stores runtime security state in:

```text
agent_state.json
```

The file is excluded from Git because it contains local runtime information.

## Example Security Flow

```text
Agent status: ACTIVE
Action: send_email
Decision: BLOCK
Blocked attempts: 1 / 3

Agent status: ACTIVE
Action: send_email
Decision: BLOCK
Blocked attempts: 2 / 3

Agent status: ACTIVE
Action: send_email
Decision: BLOCK
Blocked attempts: 3 / 3

SECURITY ALERT: Agent has been SUSPENDED.
```

While suspended, even an ordinarily permitted action is refused until the agent is manually reset.

## Running AgentGuard

AgentGuard currently uses only Python’s standard library, so no additional packages are required.

Run:

```bash
python main.py
```

Available terminal commands include:

```text
read_file
search_logs
delete_file
run_program
send_email
reset
quit
```

## Security Log

AgentGuard writes security events to `security.log`.

Example:

```text
2026-09-10T00:08:39+03:00 | Action: send_email | Decision: BLOCK | Agent status: SUSPENDED | Blocked attempts: 3
```

The log file is excluded from Git because real audit logs may contain sensitive information.

## Roadmap

Future versions may include:

* Context-aware and dynamically adjusted risk scores
* Authenticated approvers and approval history
* Database-backed audit logs
* Complete agent action traces
* Policy management dashboard
* Real-time security alerts
* Sandboxed tool execution
* FastAPI backend
* Web-based monitoring dashboard
* AI explanations for security decisions

## Inspiration

AgentGuard’s long-term direction is inspired by AI-agent observability platforms such as LangSmith and permission audit systems such as Cerbos, while focusing specifically on AI-agent security governance.

## Author

Michael Chukwujekwu Alughere
