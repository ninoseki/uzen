"""create rules table

Revision ID: 3ba82a0e5139
Revises: 76985f5d686b
Create Date: 2020-04-08 09:02:05.127999

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "3ba82a0e5139"
down_revision = "76985f5d686b"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "rules",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade():
    op.drop_table("rules")
