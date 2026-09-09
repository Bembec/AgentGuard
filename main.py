from pathlib import Path

permissions = {
    "read_file": "ALLOW",
    "search_logs": "ALLOW",
    "delete_file": "ASK",
    "run_program": "ASK",
    "send_email": "BLOCK"
}

action = input("Enter an action: ").strip().lower()
decision = permissions.get(action, "BLOCK")

print("Decision:", decision)

log_path = Path(__file__).parent / "security.log"

with log_path.open("a", encoding="utf-8") as log:
    log.write(f"Action: {action} | Decision: {decision}\n")