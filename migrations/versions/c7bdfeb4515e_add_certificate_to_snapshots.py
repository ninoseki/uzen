"""add certificate to snapshots

Revision ID: c7bdfeb4515e
Revises: d4b75b82a761
Create Date: 2020-03-05 15:13:40.763762

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c7bdfeb4515e'
down_revision = 'd4b75b82a761'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("snapshots", sa.Column(
        "certificate",  sa.Text, nullable=True))


def downgrade():
    op.drop_column("snapshots", "certificate")
