"""empty message

Revision ID: 04fa9474d949
Revises: 6d869d0895fb
Create Date: 2025-09-20 19:50:47.092743-05:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '04fa9474d949'
down_revision: Union[str, Sequence[str], None] = '6d869d0895fb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass