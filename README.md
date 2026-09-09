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

* Weighted `agent_risk_score`
* Different risk levels for different actions
* Human approval workflow for `ASK` decisions
* Authentication for manual reset
* Persistent agent suspension
* Database-backed audit logs
* Agent action traces
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
