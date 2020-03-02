"""create snapshots table

Revision ID: 003ba4793075
Revises:
Create Date: 2020-03-02 14:56:09.875867

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003ba4793075'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "snapshots",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("status", sa.Integer, nullable=False),
        sa.Column("hostname", sa.Text, nullable=False),
        sa.Column("ip_address", sa.String(255), nullable=False),
        sa.Column("asn", sa.Text, nullable=False),
        sa.Column("server", sa.Text, nullable=True),
        sa.Column("content_type", sa.Text, nullable=True),
        sa.Column("content_length", sa.Integer, nullable=True),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("headers", sa.Text, nullable=False),
        sa.Column("screenshot", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )


def downgrade():
    op.drop_table("snapshots")
