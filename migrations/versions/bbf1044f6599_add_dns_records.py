"""add dns_records

Revision ID: bbf1044f6599
Revises: 830b79ba652c
Create Date: 2020-03-19 14:00:30.350290

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "bbf1044f6599"
down_revision = "830b79ba652c"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dns_records",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id")),
        sa.Column("type", sa.String(5), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade():
    op.drop_table("dns_records")
