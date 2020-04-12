"""create matches table

Revision ID: d78a3a9a5685
Revises: 3ba82a0e5139
Create Date: 2020-04-08 16:36:09.807829

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d78a3a9a5685"
down_revision = "3ba82a0e5139"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "matches",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("matches", sa.Text(), nullable=False),
        sa.Column(
            "snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id", ondelete="CASCADE")
        ),
        sa.Column("rule_id", sa.Integer, sa.ForeignKey("rules.id", ondelete="CASCADE")),
        sa.Column("script_id", sa.Integer, sa.ForeignKey("scripts.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade():
    op.drop_table("matches")
