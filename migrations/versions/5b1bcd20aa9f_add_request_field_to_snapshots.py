"""add request field to snapshots

Revision ID: 5b1bcd20aa9f
Revises: c7bdfeb4515e
Create Date: 2020-03-08 08:09:20.882872

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column


# revision identifiers, used by Alembic.
revision = '5b1bcd20aa9f'
down_revision = 'c7bdfeb4515e'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("snapshots", sa.Column("request", sa.Text, nullable=True))

    snapshots = table("snapshots", column("request"))
    op.execute(snapshots.update().values(request="{}"))

    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.alter_column("request", nullable=False)


def downgrade():
    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.drop_column("request")
