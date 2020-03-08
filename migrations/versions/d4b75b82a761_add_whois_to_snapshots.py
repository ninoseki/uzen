"""add whois to snapshots

Revision ID: d4b75b82a761
Revises: 003ba4793075
Create Date: 2020-03-04 14:01:15.419222

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd4b75b82a761'
down_revision = '003ba4793075'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("snapshots", sa.Column("whois",  sa.Text, nullable=True))


def downgrade():
    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.drop_column("whois")
