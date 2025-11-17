"""add csrf_token_hash to refresh_tokens

Revision ID: 4559893fa2ed
Revises: ed058beacc3d
Create Date: 2025-11-17 01:56:05.752527-06:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '4559893fa2ed'
down_revision: Union[str, Sequence[str], None] = 'ed058beacc3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add csrf_token_hash column to refresh_tokens table
    op.add_column('refresh_tokens', sa.Column('csrf_token_hash', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.create_index(op.f('ix_refresh_tokens_csrf_token_hash'), 'refresh_tokens', ['csrf_token_hash'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    # Remove csrf_token_hash column from refresh_tokens table
    op.drop_index(op.f('ix_refresh_tokens_csrf_token_hash'), table_name='refresh_tokens')
    op.drop_column('refresh_tokens', 'csrf_token_hash')