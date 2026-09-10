import json
import os
from datetime import datetime
from getpass import getpass
from pathlib import Path
from database import (
    get_audit_summary,
    get_recent_audit_events,
    initialize_database,
    save_audit_event,
)


permissions = {
    "read_file": "ALLOW",
    "search_logs": "ALLOW",
    "delete_file": "ASK",
    "run_program": "ASK",
    "send_email": "BLOCK",
    "view_audit": "ALLOW",
    "audit_summary": "ALLOW",
}

risk_weights = {
    "read_file": 0,
    "search_logs": 0,
    "delete_file": 20,
    "run_program": 25,
    "send_email": 40,
    "view_audit": 0,
    "audit_summary": 0,
}

max_blocked_attempts = 3
max_risk_score = 100

blocked_attempts = 0
risk_score = 0
agent_status = "ACTIVE"

project_path = Path(__file__).parent
log_path = project_path / "security.log"
state_path = project_path / "agent_state.json"


def get_risk_level(score):
    """Convert the numerical risk score into a risk level."""

    if score >= 100:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def request_human_approval(action):
    """Ask a human to approve or deny a sensitive action."""

    while True:
        response = input(
            f"Approve '{action}'? Enter yes or no: "
        ).strip().lower()

        if response in ("yes", "y"):
            return "APPROVED"

        if response in ("no", "n"):
            return "DENIED"

        print("Invalid response. Please enter yes or no.")


def authenticate_admin():
    """Verify the administrator before resetting AgentGuard."""

    admin_pin = os.getenv("AGENTGUARD_ADMIN_PIN")

    if not admin_pin:
        print(
            "Reset unavailable: administrator PIN "
            "is not configured."
        )
        return False

    entered_pin = getpass("Enter administrator PIN: ")

    return entered_pin == admin_pin


def load_state():
    """Load the agent's previous security state."""

    default_state = {
        "agent_status": "ACTIVE",
        "blocked_attempts": 0,
        "risk_score": 0,
    }

    if not state_path.exists():
        return default_state

    try:
        with state_path.open(
            "r", encoding="utf-8"
        ) as file:
            saved_state = json.load(file)

        if not isinstance(saved_state, dict):
            raise ValueError("State must be a dictionary.")

        return saved_state

    except (OSError, json.JSONDecodeError, ValueError):
        print("Warning: saved state could not be loaded.")
        return default_state


def save_state():
    """Save the agent's current security state."""

    state = {
        "agent_status": agent_status,
        "blocked_attempts": blocked_attempts,
        "risk_score": risk_score,
    }

    with state_path.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=4)


def write_log(
    action,
    decision,
    approval="NOT_REQUIRED",
    risk_added=0,
):
    """Record every action and security decision."""

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    # Save the event in the text log
    with log_path.open("a", encoding="utf-8") as log:
        log.write(
            f"{timestamp} | "
            f"Action: {action} | "
            f"Decision: {decision} | "
            f"Approval: {approval} | "
            f"Risk score: {risk_score} | "
            f"Risk level: {get_risk_level(risk_score)} | "
            f"Agent status: {agent_status} | "
            f"Blocked attempts: {blocked_attempts}\n"
        )

    # Save the same event in the SQLite database
    save_audit_event(
        timestamp=timestamp,
        action=action,
        decision=decision,
        approval=approval,
        risk_added=risk_added,
        risk_score=risk_score,
        risk_level=get_risk_level(risk_score),
        agent_status=agent_status,
        blocked_attempts=blocked_attempts,
    )


def display_recent_audit_events():
    """Display the five most recent audit events."""

    events = get_recent_audit_events(limit=5)

    print("\nAgentGuard — Recent Audit Events")

    if not events:
        print("No audit events found.")
        return

    for event in events:
        (
            timestamp,
            action,
            decision,
            approval,
            event_risk_score,
            risk_level,
            event_agent_status,
        ) = event

        print(
            f"{timestamp} | "
            f"Action: {action} | "
            f"Decision: {decision} | "
            f"Approval: {approval} | "
            f"Risk: {event_risk_score} "
            f"({risk_level}) | "
            f"Status: {event_agent_status}"
        )


def display_audit_summary():
    """Display summary statistics from the audit database."""

    summary = get_audit_summary()

    print("\nAgentGuard — Audit Summary")
    print("Total events:", summary["total_events"])
    print("Allowed actions:", summary["allowed"])
    print("Approval requests:", summary["asked"])
    print("Blocked actions:", summary["blocked"])
    print("Refused actions:", summary["refused"])
    print(
        "Highest risk score:",
        summary["highest_risk_score"],
    )


initialize_database()

saved_state = load_state()

agent_status = saved_state.get(
    "agent_status", "ACTIVE"
)
blocked_attempts = saved_state.get(
    "blocked_attempts", 0
)
risk_score = saved_state.get(
    "risk_score", 0
)

print("AgentGuard security state loaded.")
print("Current status:", agent_status)
print("Current risk score:", risk_score)
print("Blocked attempts:", blocked_attempts)


while True:
    print("\nAgent status:", agent_status)

    action = input(
        "Enter an action, 'reset', or 'quit': "
    ).strip().lower()

    if action == "quit":
        save_state()
        print("AgentGuard state saved.")
        print("AgentGuard closed.")
        break

    if action == "reset" and agent_status == "ACTIVE":
        print("Reset not required: agent is already ACTIVE.")
        write_log(action, "RESET", "NOT_REQUIRED")
        continue

    if agent_status == "SUSPENDED":
        if action == "reset":
            if authenticate_admin():
                agent_status = "ACTIVE"
                blocked_attempts = 0
                risk_score = 0
                save_state()

                print("Administrator verified.")
                print("Agent has been manually reset.")

                write_log(
                    action,
                    "RESET",
                    "APPROVED",
                )
            else:
                print(
                    "Reset denied: administrator "
                    "verification failed."
                )

                write_log(
                    action,
                    "RESET",
                    "DENIED",
                )
        else:
            print(
                "Action refused: agent is SUSPENDED."
            )

            write_log(action, "REFUSED")

        continue

    decision = permissions.get(action, "BLOCK")
    action_risk = risk_weights.get(action, 50)

    risk_score += action_risk
    risk_level = get_risk_level(risk_score)

    print("Policy decision:", decision)

    approval_result = "NOT_REQUIRED"

    if decision == "ASK":
        approval_result = request_human_approval(
            action
        )
        print("Final decision:", approval_result)

    print("Risk added:", action_risk)
    print("Total risk score:", risk_score)
    print("Risk level:", risk_level)

    if decision == "BLOCK":
        blocked_attempts += 1

        print(
            "Blocked attempts:",
            blocked_attempts,
            "/",
            max_blocked_attempts,
        )

    if (
        blocked_attempts >= max_blocked_attempts
        or risk_score >= max_risk_score
    ):
        agent_status = "SUSPENDED"

        print(
            "SECURITY ALERT: Agent has been SUSPENDED."
        )

    save_state()

    write_log(
        action,
        decision,
        approval_result,
        action_risk,
    )

    if action == "view_audit":
        display_recent_audit_events()

    if action == "audit_summary":
        display_audit_summary()