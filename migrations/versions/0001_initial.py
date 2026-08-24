"""Initial SnowImpact schema."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("analyses",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("organization_id", sa.String(64), nullable=False, server_default="default"),
        sa.Column("environment", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("request_json", sa.JSON(), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_analyses_environment", "analyses", ["environment"])
    op.create_index("ix_analyses_decision", "analyses", ["decision"])
    op.create_table("audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.String(64), nullable=False, server_default="default"),
        sa.Column("actor", sa.String(255), nullable=False, server_default="system"),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource", sa.String(255), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table("policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.String(64), nullable=False, server_default="default"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("yaml_text", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("policies")
    op.drop_table("audit_events")
    op.drop_index("ix_analyses_decision", table_name="analyses")
    op.drop_index("ix_analyses_environment", table_name="analyses")
    op.drop_table("analyses")
