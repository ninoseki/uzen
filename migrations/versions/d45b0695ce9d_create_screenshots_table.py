"""create screenshots table

Revision ID: d45b0695ce9d
Revises: d78a3a9a5685
Create Date: 2020-04-11 17:31:04.164789

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d45b0695ce9d"
down_revision = "d78a3a9a5685"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "screenshots",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id")),
        sa.Column("data", sa.Text, nullable=False),
    )

    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.drop_column("screenshot")


def downgrade():
    op.drop_table("screenshots")

    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.add_column(
            sa.Column("screenshot", sa.Text, server_default="", nullable=False)
        )
