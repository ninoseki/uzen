"""add certificate to snapshots

Revision ID: c7bdfeb4515e
Revises: d4b75b82a761
Create Date: 2020-03-05 15:13:40.763762

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c7bdfeb4515e'
down_revision = 'd4b75b82a761'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("snapshots", sa.Column(
        "certificate",  sa.Text, nullable=True))


def downgrade():
    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.drop_column("certificate")
