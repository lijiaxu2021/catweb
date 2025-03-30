"""添加评论功能扩展"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    # 为评论表添加新字段
    op.add_column('comment', sa.Column('parent_id', sa.Integer(), nullable=True))
    op.add_column('comment', sa.Column('has_image', sa.Boolean(), default=False))
    op.add_column('comment', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.create_foreign_key('fk_comment_parent', 'comment', 'comment', ['parent_id'], ['id'])
    
    # 创建评论图片表
    op.create_table('comment_image',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('comment_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['comment_id'], ['comment.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    # 删除评论图片表
    op.drop_table('comment_image')
    
    # 删除评论表的新字段
    op.drop_constraint('fk_comment_parent', 'comment', type_='foreignkey')
    op.drop_column('comment', 'updated_at')
    op.drop_column('comment', 'has_image')
    op.drop_column('comment', 'parent_id') 