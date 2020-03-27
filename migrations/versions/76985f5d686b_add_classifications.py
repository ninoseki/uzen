"""add classifications

Revision ID: 76985f5d686b
Revises: bbf1044f6599
Create Date: 2020-03-25 15:48:19.572035

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "76985f5d686b"
down_revision = "bbf1044f6599"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "classifications",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id")),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("malicious", sa.Boolean, nullable=False),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade():
    op.drop_table("classifications")
