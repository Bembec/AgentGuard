import sqlite3
from pathlib import Path


database_path = (
    Path(__file__).parent / "agentguard.db"
)


def initialize_database():
    """Create or upgrade the AgentGuard audit database."""

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL DEFAULT 'legacy_agent',
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                decision TEXT NOT NULL,
                approval TEXT NOT NULL,
                risk_added INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                agent_status TEXT NOT NULL,
                blocked_attempts INTEGER NOT NULL
            )
            """
        )

        columns = connection.execute(
            "PRAGMA table_info(audit_events)"
        ).fetchall()

        column_names = [
            column[1] for column in columns
        ]

        if "agent_name" not in column_names:
            connection.execute(
                """
                ALTER TABLE audit_events
                ADD COLUMN agent_name TEXT
                NOT NULL DEFAULT 'legacy_agent'
                """
            )


def save_audit_event(
    agent_name,
    timestamp,
    action,
    decision,
    approval,
    risk_added,
    risk_score,
    risk_level,
    agent_status,
    blocked_attempts,
):
    """Save one AgentGuard security event."""

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO audit_events (
                agent_name,
                timestamp,
                action,
                decision,
                approval,
                risk_added,
                risk_score,
                risk_level,
                agent_status,
                blocked_attempts
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                agent_name,
                timestamp,
                action,
                decision,
                approval,
                risk_added,
                risk_score,
                risk_level,
                agent_status,
                blocked_attempts,
            ),
        )

def get_recent_audit_events(agent_name, limit=5):
    """Return the most recent events for one agent."""

    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute(
            """
            SELECT
                agent_name,
                timestamp,
                action,
                decision,
                approval,
                risk_score,
                risk_level,
                agent_status
            FROM audit_events
            WHERE agent_name = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (agent_name, limit),
        )

        return cursor.fetchall()


def get_audit_summary(agent_name):
    """Return audit statistics for one agent."""

    with sqlite3.connect(database_path) as connection:
        summary = connection.execute(
            """
            SELECT
                COUNT(*),
                SUM(
                    CASE WHEN decision = 'ALLOW'
                    THEN 1 ELSE 0 END
                ),
                SUM(
                    CASE WHEN decision = 'ASK'
                    THEN 1 ELSE 0 END
                ),
                SUM(
                    CASE WHEN decision = 'BLOCK'
                    THEN 1 ELSE 0 END
                ),
                SUM(
                    CASE WHEN decision = 'REFUSED'
                    THEN 1 ELSE 0 END
                ),
                COALESCE(MAX(risk_score), 0)
            FROM audit_events
            WHERE agent_name = ?
            """,
            (agent_name,),
        ).fetchone()

    return {
        "total_events": summary[0],
        "allowed": summary[1] or 0,
        "asked": summary[2] or 0,
        "blocked": summary[3] or 0,
        "refused": summary[4] or 0,
        "highest_risk_score": summary[5],
    }

if __name__ == "__main__":
    initialize_database()
    print(
        "AgentGuard audit database initialized:"
    )
    print(database_path)