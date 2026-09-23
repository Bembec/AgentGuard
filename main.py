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


def get_risk_level(score):
    """Convert a numerical risk score into a risk level."""

    if score >= 100:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    return "LOW"


def get_agent_state(agent_name):
    """Return one registered agent's security state."""

    normalized_name = normalize_agent_name(
        agent_name
    )

    if normalized_name not in agent_states:
        raise KeyError(
            f"Unknown agent: {normalized_name}"
        )

    return agent_states[normalized_name]


def get_current_state():
    """Return the active agent's security state."""

    return get_agent_state(active_agent_name)


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

        print(
            "Invalid response. Please enter yes or no."
        )


def authenticate_admin():
    """Verify the administrator before resetting AgentGuard."""

    admin_pin = os.getenv("AGENTGUARD_ADMIN_PIN")

    if not admin_pin:
        print(
            "Administrator PIN is not configured."
        )
        return False

    entered_pin = getpass(
        "Enter administrator PIN: "
    )

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
            "r",
            encoding="utf-8",
        ) as file:
            saved_state = json.load(file)

        if not isinstance(saved_state, dict):
            raise ValueError(
                "State must be a dictionary."
            )

        if (
            "agents" in saved_state
            and isinstance(
                saved_state["agents"],
                dict,
            )
        ):
            return saved_state

        if "agent_status" in saved_state:
            return {
                "active_agent": "legacy_agent",
                "agents": {
                    "legacy_agent": {
                        "agent_status": (
                            saved_state.get(
                                "agent_status",
                                "ACTIVE",
                            )
                        ),
                        "blocked_attempts": (
                            saved_state.get(
                                "blocked_attempts",
                                0,
                            )
                        ),
                        "risk_score": (
                            saved_state.get(
                                "risk_score",
                                0,
                            )
                        ),
                    }
                },
            }

        raise ValueError("Unknown state format.")

    except (
        OSError,
        json.JSONDecodeError,
        ValueError,
    ):
        print(
            "Warning: saved state could not be loaded."
        )
        return default_data


def save_state():
    """Save every agent's security state."""

    state_data = {
        "active_agent": active_agent_name,
        "agents": agent_states,
    }

    with state_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            state_data,
            file,
            indent=4,
        )


def initialize_agentguard():
    """Initialize the database and load all agent states."""

    global agent_states
    global active_agent_name

    initialize_database()

    saved_state = load_state()

    agent_states = saved_state["agents"]
    active_agent_name = saved_state[
        "active_agent"
    ]

    if active_agent_name not in agent_states:
        agent_states[active_agent_name] = (
            create_agent_state()
        )

    save_state()


def register_agent(agent_name):
    """Register a new agent if it does not exist."""

    normalized_name = normalize_agent_name(
        agent_name
    )

    if not normalized_name:
        raise ValueError(
            "Agent name cannot be empty."
        )

    created = False

    if normalized_name not in agent_states:
        agent_states[normalized_name] = (
            create_agent_state()
        )
        created = True
        save_state()

    return {
        "agent_name": normalized_name,
        "created": created,
        "state": agent_states[normalized_name],
    }


def write_log(
    agent_name,
    action,
    decision,
    approval="NOT_REQUIRED",
    risk_added=0,
):
    """Record one security event for a selected agent."""

    normalized_name = normalize_agent_name(
        agent_name
    )

    current_state = get_agent_state(
        normalized_name
    )

    timestamp = (
        datetime.now()
        .astimezone()
        .isoformat(timespec="seconds")
    )

    risk_score = current_state["risk_score"]
    agent_status = current_state[
        "agent_status"
    ]
    blocked_attempts = current_state[
        "blocked_attempts"
    ]

    with log_path.open(
        "a",
        encoding="utf-8",
    ) as log:
        log.write(
            f"{timestamp} | "
            f"Agent: {normalized_name} | "
            f"Action: {action} | "
            f"Decision: {decision} | "
            f"Approval: {approval} | "
            f"Risk score: {risk_score} | "
            f"Risk level: "
            f"{get_risk_level(risk_score)} | "
            f"Agent status: {agent_status} | "
            f"Blocked attempts: "
            f"{blocked_attempts}\n"
        )

    save_audit_event(
        agent_name=normalized_name,
        timestamp=timestamp,
        action=action,
        decision=decision,
        approval=approval,
        risk_added=risk_added,
        risk_score=risk_score,
        risk_level=get_risk_level(
            risk_score
        ),
        agent_status=agent_status,
        blocked_attempts=blocked_attempts,
    )


def evaluate_action(
    agent_name,
    action,
    approval=None,
):
    """Evaluate one action for one registered agent."""

    normalized_name = normalize_agent_name(
        agent_name
    )

    normalized_action = action.strip().lower()

    current_state = get_agent_state(
        normalized_name
    )

    if current_state["agent_status"] == "SUSPENDED":
        write_log(
            agent_name=normalized_name,
            action=normalized_action,
            decision="REFUSED",
            approval="NOT_REQUIRED",
            risk_added=0,
        )

        return {
            "agent_name": normalized_name,
            "action": normalized_action,
            "policy_decision": "REFUSED",
            "approval": "NOT_REQUIRED",
            "risk_added": 0,
            "risk_score": current_state[
                "risk_score"
            ],
            "risk_level": get_risk_level(
                current_state["risk_score"]
            ),
            "blocked_attempts": current_state[
                "blocked_attempts"
            ],
            "agent_status": current_state[
                "agent_status"
            ],
            "message": (
                "Action refused because the "
                "agent is suspended."
            ),
        }

    policy_decision = permissions.get(
        normalized_action,
        "BLOCK",
    )

    action_risk = risk_weights.get(
        normalized_action,
        50,
    )

    current_state["risk_score"] += action_risk

    approval_result = "NOT_REQUIRED"

    if policy_decision == "ASK":
        if approval in (
            "APPROVED",
            "DENIED",
        ):
            approval_result = approval
        else:
            approval_result = "PENDING"

    if policy_decision == "BLOCK":
        current_state["blocked_attempts"] += 1

    if (
        current_state["blocked_attempts"]
        >= max_blocked_attempts
        or current_state["risk_score"]
        >= max_risk_score
    ):
        current_state["agent_status"] = "SUSPENDED"

    save_state()

    write_log(
        agent_name=normalized_name,
        action=normalized_action,
        decision=policy_decision,
        approval=approval_result,
        risk_added=action_risk,
    )

    if policy_decision == "ALLOW":
        message = "Action allowed by policy."

    elif policy_decision == "ASK":
        if approval_result == "APPROVED":
            message = (
                "Action approved by a human."
            )
        elif approval_result == "DENIED":
            message = (
                "Action denied by a human."
            )
        else:
            message = (
                "Action requires human approval."
            )

    else:
        message = "Action blocked by policy."

    if (
        current_state["agent_status"]
        == "SUSPENDED"
    ):
        message += (
            " Agent has reached a security "
            "threshold and is now suspended."
        )

    return {
        "agent_name": normalized_name,
        "action": normalized_action,
        "policy_decision": policy_decision,
        "approval": approval_result,
        "risk_added": action_risk,
        "risk_score": current_state[
            "risk_score"
        ],
        "risk_level": get_risk_level(
            current_state["risk_score"]
        ),
        "blocked_attempts": current_state[
            "blocked_attempts"
        ],
        "agent_status": current_state[
            "agent_status"
        ],
        "message": message,
    }


def reset_agent(agent_name):
    """Reset one suspended agent's security state."""

    normalized_name = normalize_agent_name(
        agent_name
    )

    current_state = get_agent_state(
        normalized_name
    )

    if current_state["agent_status"] == "ACTIVE":
        write_log(
            agent_name=normalized_name,
            action="reset",
            decision="RESET",
            approval="NOT_REQUIRED",
            risk_added=0,
        )

        return {
            "agent_name": normalized_name,
            "reset": False,
            "message": (
                "Reset not required because "
                "the agent is already active."
            ),
            "state": current_state,
        }

    current_state["agent_status"] = "ACTIVE"
    current_state["blocked_attempts"] = 0
    current_state["risk_score"] = 0

    save_state()

    write_log(
        agent_name=normalized_name,
        action="reset",
        decision="RESET",
        approval="APPROVED",
        risk_added=0,
    )

    return {
        "agent_name": normalized_name,
        "reset": True,
        "message": (
            "Agent has been manually reset."
        ),
        "state": current_state,
    }


def display_agents():
    """Display every registered agent and its state."""

    print("\nAgentGuard — Registered Agents")

    for agent_name, state in sorted(
        agent_states.items()
    ):
        marker = ""

        if agent_name == active_agent_name:
            marker = " (CURRENT)"

        print(
            f"{agent_name}{marker} | "
            f"Status: "
            f"{state['agent_status']} | "
            f"Risk: {state['risk_score']} "
            f"("
            f"{get_risk_level(state['risk_score'])}"
            f") | "
            f"Blocked: "
            f"{state['blocked_attempts']}"
        )


def switch_agent():
    """Switch to an existing agent or create a new one."""

    global active_agent_name

    entered_name = input(
        "Enter the agent name: "
    ).strip()

    try:
        registration = register_agent(
            entered_name
        )
    except ValueError as error:
        print(error)
        return

    active_agent_name = registration[
        "agent_name"
    ]

    save_state()

    if registration["created"]:
        print(
            "New agent registered:",
            active_agent_name,
        )

    print(
        "Active agent changed to:",
        active_agent_name,
    )


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
        print(
            "No audit events found for this agent."
        )
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

    summary = get_audit_summary(
        active_agent_name
    )

    print(
        "\nAgentGuard — Audit Summary:",
        active_agent_name,
    )

    print(
        "Total events:",
        summary["total_events"],
    )

    print(
        "Allowed actions:",
        summary["allowed"],
    )

    print(
        "Approval requests:",
        summary["asked"],
    )

    print(
        "Blocked actions:",
        summary["blocked"],
    )

    print(
        "Refused actions:",
        summary["refused"],
    )

    print(
        "Highest risk score:",
        summary["highest_risk_score"],
    )


def display_action_result(result):
    """Display the result of an evaluated action."""

    print(
        "Policy decision:",
        result["policy_decision"],
    )

    if result["policy_decision"] == "ASK":
        print(
            "Final approval:",
            result["approval"],
        )

    print(
        "Risk added:",
        result["risk_added"],
    )

    print(
        "Total risk score:",
        result["risk_score"],
    )

    print(
        "Risk level:",
        result["risk_level"],
    )

    print(
        "Blocked attempts:",
        result["blocked_attempts"],
        "/",
        max_blocked_attempts,
    )

    print(
        "Agent status:",
        result["agent_status"],
    )

    print(
        "Message:",
        result["message"],
    )


def run_cli():
    """Start the AgentGuard command-line interface."""

    global active_agent_name

    initialize_agentguard()

    print(
        "AgentGuard multi-agent state loaded."
    )

    print(
        "Active agent:",
        active_agent_name,
    )

    while True:
        current_state = get_current_state()

        print(
            "\nActive agent:",
            active_agent_name,
        )

        print(
            "Agent status:",
            current_state["agent_status"],
        )

        print(
            "Risk score:",
            current_state["risk_score"],
        )

        action = input(
            "Enter an action, 'list_agents', "
            "'switch_agent', 'reset', or "
            "'quit': "
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

        if action == "reset":
            if (
                current_state["agent_status"]
                == "ACTIVE"
            ):
                result = reset_agent(
                    active_agent_name
                )

                print(result["message"])
                continue

            if authenticate_admin():
                result = reset_agent(
                    active_agent_name
                )

                print(
                    "Administrator verified."
                )

                print(result["message"])
            else:
                print(
                    "Reset denied: administrator "
                    "verification failed."
                )

                write_log(
                    agent_name=active_agent_name,
                    action="reset",
                    decision="RESET",
                    approval="DENIED",
                    risk_added=0,
                )

            continue

        if (
            current_state["agent_status"]
            == "SUSPENDED"
        ):
            result = evaluate_action(
                active_agent_name,
                action,
            )

            display_action_result(result)
            continue

        policy_decision = permissions.get(
            action,
            "BLOCK",
        )

        approval_result = None

        if policy_decision == "ASK":
            approval_result = (
                request_human_approval(action)
            )

        result = evaluate_action(
            agent_name=active_agent_name,
            action=action,
            approval=approval_result,
        )

        display_action_result(result)

        if action == "view_audit":
            display_recent_audit_events()

        if action == "audit_summary":
            display_audit_summary()


if __name__ == "__main__":
    run_cli()