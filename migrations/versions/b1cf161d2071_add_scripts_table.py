"""add scripts table

Revision ID: b1cf161d2071
Revises: 5b1bcd20aa9f
Create Date: 2020-03-08 20:20:01.328748

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b1cf161d2071'
down_revision = '5b1bcd20aa9f'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scripts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id")),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade():
    pass
