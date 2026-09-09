from datetime import datetime
from pathlib import Path


permissions = {
    "read_file": "ALLOW",
    "search_logs": "ALLOW",
    "delete_file": "ASK",
    "run_program": "ASK",
    "send_email": "BLOCK",
}

max_blocked_attempts = 3
blocked_attempts = 0
agent_status = "ACTIVE"

log_path = Path(__file__).parent / "security.log"


def write_log(action, decision):
    """Record every action and security decision."""

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    with log_path.open("a", encoding="utf-8") as log:
        log.write(
            f"{timestamp} | "
            f"Action: {action} | "
            f"Decision: {decision} | "
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

            print("Agent has been manually reset.")
            write_log(action, "RESET")
        else:
            print("Action refused: agent is SUSPENDED.")
            write_log(action, "REFUSED")

        continue

    decision = permissions.get(action, "BLOCK")

    print("Decision:", decision)

    if decision == "BLOCK":
        blocked_attempts += 1
        print(
            "Blocked attempts:",
            blocked_attempts,
            "/",
            max_blocked_attempts,
        )

    if blocked_attempts >= max_blocked_attempts:
        agent_status = "SUSPENDED"
        print(
            "SECURITY ALERT: Agent has been SUSPENDED."
        )

    write_log(action, decision)