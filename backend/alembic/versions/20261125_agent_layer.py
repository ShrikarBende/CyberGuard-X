"""Add bounded agent investigation persistence.

Revision ID: 20261125_agent_layer
Revises: 3e3f12404ef0
Create Date: 2026-11-25
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "20261125_agent_layer"
down_revision: Union[str, None] = "3e3f12404ef0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_runs",
        sa.Column("run_id", sa.String(128), primary_key=True),
        sa.Column("incident_id", sa.String(128), sa.ForeignKey("incidents.incident_id"), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("model_name", sa.String(128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("limits", sa.JSON(), nullable=False),
        sa.Column("usage", sa.JSON(), nullable=False),
        sa.Column("report", sa.JSON(), nullable=True),
        sa.Column("validation", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_agent_runs_incident_id", "agent_runs", ["incident_id"])
    op.create_index("ix_agent_runs_status", "agent_runs", ["status"])
    op.create_table(
        "agent_steps",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("run_id", sa.String(128), sa.ForeignKey("agent_runs.run_id", ondelete="CASCADE"), nullable=False),
        sa.Column("step_no", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=True),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("result_summary", sa.Text(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_steps_run_id", "agent_steps", ["run_id"])
    op.create_table(
        "action_proposals",
        sa.Column("proposal_id", sa.String(128), primary_key=True),
        sa.Column("run_id", sa.String(128), sa.ForeignKey("agent_runs.run_id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.String(128), sa.ForeignKey("incidents.incident_id"), nullable=False),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target", sa.String(256), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("decided_by", sa.String(64), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("execution_state", sa.String(16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_action_proposals_run_id", "action_proposals", ["run_id"])
    op.create_index("ix_action_proposals_incident_id", "action_proposals", ["incident_id"])
    op.create_index("ix_action_proposals_status", "action_proposals", ["status"])


def downgrade() -> None:
    op.drop_index("ix_action_proposals_status", table_name="action_proposals")
    op.drop_index("ix_action_proposals_incident_id", table_name="action_proposals")
    op.drop_index("ix_action_proposals_run_id", table_name="action_proposals")
    op.drop_table("action_proposals")
    op.drop_index("ix_agent_steps_run_id", table_name="agent_steps")
    op.drop_table("agent_steps")
    op.drop_index("ix_agent_runs_status", table_name="agent_runs")
    op.drop_index("ix_agent_runs_incident_id", table_name="agent_runs")
    op.drop_table("agent_runs")
