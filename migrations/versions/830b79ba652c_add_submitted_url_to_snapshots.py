"""add submitted_url to snapshots

Revision ID: 830b79ba652c
Revises: b1cf161d2071
Create Date: 2020-03-14 09:04:29.633742

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "830b79ba652c"
down_revision = "b1cf161d2071"
branch_labels = None
depends_on = None


snapshot_helper = sa.Table(
    "snapshots",
    sa.MetaData(),
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("url", sa.Text),
    sa.Column("submitted_url", sa.Text),
)


def upgrade():
    connection = op.get_bind()

    op.add_column("snapshots", sa.Column("submitted_url", sa.Text, nullable=True))

    for snapshot in connection.execute(snapshot_helper.select()):
        connection.execute(
            snapshot_helper.update()
            .where(snapshot_helper.c.id == snapshot.id)
            .values(url=snapshot.url, submitted_url=snapshot.url)
        )

    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.alter_column("submitted_url", nullable=False)


def downgrade():
    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.drop_column("submitted_url")
