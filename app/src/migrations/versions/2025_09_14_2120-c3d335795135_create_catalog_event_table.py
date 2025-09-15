"""create catalog event table

Revision ID: c3d335795135
Revises: 
Create Date: 2025-09-14 21:20:57.340487-05:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'c3d335795135'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('catalogevent',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('action', sa.Enum('check_out', 'reserve', 'renew', 'return', name='catalogactionsenum'), nullable=False),
    sa.Column('event_timestamp', sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column('user', sa.Integer(), nullable=True),
    sa.Column('catalog_ids', sa.ARRAY(sa.Integer()), nullable=True),
    sa.Column('admin_id', sa.Integer(), nullable=False),
    sa.Column('due_date', sa.TIMESTAMP(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['admin_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['user'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('catalogevent')