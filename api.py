import os
from typing import Literal

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Query,
)
from pydantic import BaseModel, Field

import main
from database import (
    get_audit_summary,
    get_recent_audit_events,
)


app = FastAPI(
    title="AgentGuard Control Plane API",
    description=(
        "A multi-agent permission, risk, "
        "suspension, and audit control plane."
    ),
    version="8.0",
)


class AgentRegistration(BaseModel):
    """Information required to register an agent."""

    agent_name: str = Field(
        min_length=1,
        max_length=100,
        examples=["research_agent"],
    )


class ActionRequest(BaseModel):
    """An action requested by one agent."""

    agent_name: str = Field(
        min_length=1,
        max_length=100,
        examples=["research_agent"],
    )

    action: str = Field(
        min_length=1,
        max_length=100,
        examples=["read_file"],
    )

    approval: Literal[
        "APPROVED",
        "DENIED",
    ] | None = Field(
        default=None,
        description=(
            "Human decision for actions that "
            "require approval."
        ),
        examples=["APPROVED"],
    )


@app.on_event("startup")
def startup_event():
    """Initialize AgentGuard when the API starts."""

    main.initialize_agentguard()


def require_admin(
    x_admin_pin: str | None = Header(
        default=None,
    ),
):
    """Verify the administrative API PIN."""

    configured_pin = os.getenv(
        "AGENTGUARD_ADMIN_PIN"
    )

    if not configured_pin:
        raise HTTPException(
            status_code=503,
            detail=(
                "Administrator PIN is not "
                "configured."
            ),
        )

    if x_admin_pin != configured_pin:
        raise HTTPException(
            status_code=401,
            detail="Administrator authentication failed.",
        )


def serialize_agent(
    agent_name,
    state,
):
    """Convert one agent state into API data."""

    return {
        "agent_name": agent_name,
        "agent_status": state[
            "agent_status"
        ],
        "risk_score": state["risk_score"],
        "risk_level": main.get_risk_level(
            state["risk_score"]
        ),
        "blocked_attempts": state[
            "blocked_attempts"
        ],
    }


@app.get("/")
def home():
    """Return basic AgentGuard API information."""

    return {
        "application": "AgentGuard",
        "version": "8.0",
        "status": "running",
        "purpose": (
            "Multi-agent permission and "
            "security control plane"
        ),
        "documentation": "/docs",
    }


@app.get("/health")
def health():
    """Return API health information."""

    return {
        "status": "healthy",
        "registered_agents": len(
            main.agent_states
        ),
    }


@app.get("/permissions")
def permissions():
    """Return the current action policy."""

    return {
        "permissions": main.permissions,
        "risk_weights": main.risk_weights,
        "max_blocked_attempts": (
            main.max_blocked_attempts
        ),
        "max_risk_score": (
            main.max_risk_score
        ),
    }


@app.get("/agents")
def list_agents():
    """Return every registered agent."""

    return [
        serialize_agent(
            agent_name,
            state,
        )
        for agent_name, state in sorted(
            main.agent_states.items()
        )
    ]


@app.post(
    "/agents",
    status_code=201,
)
def register_agent(
    registration: AgentRegistration,
):
    """Register a new agent."""

    try:
        result = main.register_agent(
            registration.agent_name
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    response = serialize_agent(
        result["agent_name"],
        result["state"],
    )

    response["created"] = result["created"]

    return response


@app.get("/agents/{agent_name}")
def get_agent(agent_name: str):
    """Return one registered agent."""

    normalized_name = (
        main.normalize_agent_name(agent_name)
    )

    try:
        state = main.get_agent_state(
            normalized_name
        )

    except KeyError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    return serialize_agent(
        normalized_name,
        state,
    )


@app.post("/actions/evaluate")
def evaluate_action(
    request: ActionRequest,
):
    """Evaluate an action for one agent."""

    try:
        result = main.evaluate_action(
            agent_name=request.agent_name,
            action=request.action,
            approval=request.approval,
        )

    except KeyError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    return result


@app.get("/agents/{agent_name}/audit")
def recent_audit_events(
    agent_name: str,
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    ),
):
    """Return recent audit events for one agent."""

    normalized_name = (
        main.normalize_agent_name(agent_name)
    )

    try:
        main.get_agent_state(
            normalized_name
        )

    except KeyError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    events = get_recent_audit_events(
        normalized_name,
        limit=limit,
    )

    return [
        {
            "agent_name": event[0],
            "timestamp": event[1],
            "action": event[2],
            "decision": event[3],
            "approval": event[4],
            "risk_score": event[5],
            "risk_level": event[6],
            "agent_status": event[7],
        }
        for event in events
    ]


@app.get("/agents/{agent_name}/summary")
def audit_summary(agent_name: str):
    """Return audit statistics for one agent."""

    normalized_name = (
        main.normalize_agent_name(agent_name)
    )

    try:
        main.get_agent_state(
            normalized_name
        )

    except KeyError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    summary = get_audit_summary(
        normalized_name
    )

    return {
        "agent_name": normalized_name,
        **summary,
    }


@app.post("/agents/{agent_name}/reset")
def reset_agent(
    agent_name: str,
    x_admin_pin: str | None = Header(
        default=None,
    ),
):
    """Administratively reset one agent."""

    require_admin(x_admin_pin)

    normalized_name = (
        main.normalize_agent_name(agent_name)
    )

    try:
        result = main.reset_agent(
            normalized_name
        )

    except KeyError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    return {
        "agent_name": result["agent_name"],
        "reset": result["reset"],
        "message": result["message"],
        "state": serialize_agent(
            result["agent_name"],
            result["state"],
        ),
    }