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

project_path = Path(__file__).parent
log_path = project_path / "security.log"
state_path = project_path / "agent_state.json"

agent_states = {}
active_agent_name = ""


def create_agent_state():
    """Create a clean security state for a new agent."""

    return {
        "agent_status": "ACTIVE",
        "blocked_attempts": 0,
        "risk_score": 0,
    }


def normalize_agent_name(name):
    """Convert an agent name into a consistent identifier."""

    return name.strip().lower().replace(" ", "_")


def get_current_state():
    """Return the active agent's security state."""

    return agent_states[active_agent_name]


def get_risk_level(score):
    """Convert a numerical risk score into a risk level."""

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
            "Administrator PIN is not configured."
        )
        return False

    entered_pin = getpass("Enter administrator PIN: ")

    return entered_pin == admin_pin


def load_state():
    """Load all previous agent security states."""

    default_data = {
        "active_agent": "default_agent",
        "agents": {
            "default_agent": create_agent_state(),
        },
    }

    if not state_path.exists():
        return default_data

    try:
        with state_path.open(
            "r", encoding="utf-8"
        ) as file:
            saved_state = json.load(file)

        if not isinstance(saved_state, dict):
            raise ValueError("State must be a dictionary.")

        if (
            "agents" in saved_state
            and isinstance(saved_state["agents"], dict)
        ):
            return saved_state

        # Convert the old V6 single-agent state
        # into the new V7 multi-agent format.
        if "agent_status" in saved_state:
            return {
                "active_agent": "legacy_agent",
                "agents": {
                    "legacy_agent": {
                        "agent_status": saved_state.get(
                            "agent_status", "ACTIVE"
                        ),
                        "blocked_attempts": saved_state.get(
                            "blocked_attempts", 0
                        ),
                        "risk_score": saved_state.get(
                            "risk_score", 0
                        ),
                    }
                },
            }

        raise ValueError("Unknown state format.")

    except (OSError, json.JSONDecodeError, ValueError):
        print("Warning: saved state could not be loaded.")
        return default_data


def save_state():
    """Save every agent's security state."""

    state_data = {
        "active_agent": active_agent_name,
        "agents": agent_states,
    }

    with state_path.open("w", encoding="utf-8") as file:
        json.dump(state_data, file, indent=4)


def write_log(
    action,
    decision,
    approval="NOT_REQUIRED",
    risk_added=0,
):
    """Record one security event for the active agent."""

    current_state = get_current_state()

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    risk_score = current_state["risk_score"]
    agent_status = current_state["agent_status"]
    blocked_attempts = current_state["blocked_attempts"]

    with log_path.open("a", encoding="utf-8") as log:
        log.write(
            f"{timestamp} | "
            f"Agent: {active_agent_name} | "
            f"Action: {action} | "
            f"Decision: {decision} | "
            f"Approval: {approval} | "
            f"Risk score: {risk_score} | "
            f"Risk level: {get_risk_level(risk_score)} | "
            f"Agent status: {agent_status} | "
            f"Blocked attempts: {blocked_attempts}\n"
        )

    save_audit_event(
        agent_name=active_agent_name,
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


def display_agents():
    """Display every registered agent and its state."""

    print("\nAgentGuard — Registered Agents")

    for agent_name, state in sorted(agent_states.items()):
        marker = ""

        if agent_name == active_agent_name:
            marker = " (CURRENT)"

        print(
            f"{agent_name}{marker} | "
            f"Status: {state['agent_status']} | "
            f"Risk: {state['risk_score']} "
            f"({get_risk_level(state['risk_score'])}) | "
            f"Blocked: {state['blocked_attempts']}"
        )


def switch_agent():
    """Switch to an existing agent or create a new one."""

    global active_agent_name

    new_agent_name = input(
        "Enter the agent name: "
    ).strip()

    new_agent_name = normalize_agent_name(
        new_agent_name
    )

    if not new_agent_name:
        print("Agent name cannot be empty.")
        return

    if new_agent_name not in agent_states:
        agent_states[new_agent_name] = (
            create_agent_state()
        )
        print(
            "New agent registered:",
            new_agent_name,
        )

    active_agent_name = new_agent_name
    save_state()

    print("Active agent changed to:", active_agent_name)


def display_recent_audit_events():
    """Display recent events for the active agent."""

    events = get_recent_audit_events(
        active_agent_name,
        limit=5,
    )

    print(
        "\nAgentGuard — Recent Audit Events:",
        active_agent_name,
    )

    if not events:
        print("No audit events found for this agent.")
        return

    for event in events:
        (
            event_agent_name,
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
            f"Agent: {event_agent_name} | "
            f"Action: {action} | "
            f"Decision: {decision} | "
            f"Approval: {approval} | "
            f"Risk: {event_risk_score} "
            f"({risk_level}) | "
            f"Status: {event_agent_status}"
        )


def display_audit_summary():
    """Display audit statistics for the active agent."""

    summary = get_audit_summary(active_agent_name)

    print(
        "\nAgentGuard — Audit Summary:",
        active_agent_name,
    )
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
agent_states = saved_state["agents"]
active_agent_name = saved_state["active_agent"]

if active_agent_name not in agent_states:
    agent_states[active_agent_name] = (
        create_agent_state()
    )

save_state()

print("AgentGuard multi-agent state loaded.")
print("Active agent:", active_agent_name)


while True:
    current_state = get_current_state()

    print("\nActive agent:", active_agent_name)
    print(
        "Agent status:",
        current_state["agent_status"],
    )
    print("Risk score:", current_state["risk_score"])

    action = input(
        "Enter an action, 'list_agents', "
        "'switch_agent', 'reset', or 'quit': "
    ).strip().lower()

    if action == "quit":
        save_state()
        print("AgentGuard state saved.")
        print("AgentGuard closed.")
        break

    if action == "list_agents":
        display_agents()
        continue

    if action == "switch_agent":
        switch_agent()
        continue

    if (
        action == "reset"
        and current_state["agent_status"] == "ACTIVE"
    ):
        print(
            "Reset not required: agent is already ACTIVE."
        )
        write_log(
            action,
            "RESET",
            "NOT_REQUIRED",
        )
        continue

    if current_state["agent_status"] == "SUSPENDED":
        if action == "reset":
            if authenticate_admin():
                current_state["agent_status"] = "ACTIVE"
                current_state["blocked_attempts"] = 0
                current_state["risk_score"] = 0
                save_state()

                print("Administrator verified.")
                print(
                    "Agent has been manually reset."
                )

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

    current_state["risk_score"] += action_risk

    risk_score = current_state["risk_score"]
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
        current_state["blocked_attempts"] += 1

        print(
            "Blocked attempts:",
            current_state["blocked_attempts"],
            "/",
            max_blocked_attempts,
        )

    if (
        current_state["blocked_attempts"]
        >= max_blocked_attempts
        or risk_score >= max_risk_score
    ):
        current_state["agent_status"] = "SUSPENDED"

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