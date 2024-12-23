"""Migration.

Revision ID: 49deb30844ce
Revises: 
Create Date: 2024-12-05 17:08:53.387249

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '49deb30844ce'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('login_attempt',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=256), nullable=False),
    sa.Column('success', sa.Boolean(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=128), nullable=False),
    sa.Column('password', sa.String(length=128), nullable=False),
    sa.Column('confirmed', sa.Boolean(), nullable=True),
    sa.Column('failed_attempts', sa.Integer(), nullable=True),
    sa.Column('locked_until', sa.DateTime(), nullable=True),
    sa.Column('is_admin', sa.Boolean(), nullable=True),
    sa.Column('is_two_factor_enabled', sa.Boolean(), nullable=False),
    sa.Column('secret_token', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    op.drop_table('login_attempt')
    # ### end Alembic commands ###
