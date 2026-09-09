from datetime import datetime
from pathlib import Path


permissions = {
    "read_file": "ALLOW",
    "search_logs": "ALLOW",
    "delete_file": "ASK",
    "run_program": "ASK",
    "send_email": "BLOCK",
}

risk_weights = {
    "read_file": 0,
    "search_logs": 0,
    "delete_file": 20,
    "run_program": 25,
    "send_email": 40,
}

max_blocked_attempts = 3
blocked_attempts = 0
risk_score = 0
max_risk_score = 100
agent_status = "ACTIVE"

log_path = Path(__file__).parent / "security.log"

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


def write_log(action, decision, approval="NOT_REQUIRED"):
    """Record every action and security decision."""

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

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


while True:
    print("\nAgent status:", agent_status)

    action = input(
        "Enter an action, 'reset', or 'quit': "
    ).strip().lower()

    if action == "quit":
        print("AgentGuard closed.")
        break

    if agent_status == "SUSPENDED":
        if action == "reset":
            agent_status = "ACTIVE"
            blocked_attempts = 0
            risk_score = 0

            print("Agent has been manually reset.")
            write_log(action, "RESET")
        else:
            print("Action refused: agent is SUSPENDED.")
            write_log(action, "REFUSED")

        continue

    decision = permissions.get(action, "BLOCK")
    action_risk = risk_weights.get(action, 50)

    risk_score += action_risk
    risk_level = get_risk_level(risk_score)

    print("Policy decision:", decision)

    approval_result = "NOT_REQUIRED"

    if decision == "ASK":
        approval_result = request_human_approval(action)
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

    write_log(action, decision, approval_result)