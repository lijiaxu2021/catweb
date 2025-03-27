from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
import os

# 创建一个临时应用程序实例
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'blog_new.db')
app.config['SECRET_KEY'] = 'rebuild_secret_key'
db = SQLAlchemy(app)

# 定义关联表
post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

post_likes = db.Table('post_likes',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

user_titles = db.Table('user_titles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('title_id', db.Integer, db.ForeignKey('title.id'), primary_key=True),
    db.Column('granted_at', db.DateTime, default=datetime.now(timezone.utc))
)

# 定义模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    profile_pic = db.Column(db.String(120), default='default_profile.jpg')
    bio = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    
    # 关系定义
    posts = db.relationship('Post', back_populates='author', foreign_keys='Post.author_id')
    comments = db.relationship('Comment', back_populates='author', lazy=True)
    liked_posts = db.relationship('Post', secondary=post_likes, back_populates='liking_users')
    titles = db.relationship('Title', secondary=user_titles, back_populates='users')
    
    # 当前佩戴的称号
    wearing_title_id = db.Column(db.Integer, db.ForeignKey('title.id'), nullable=True)
    wearing_title = db.relationship('Title', foreign_keys=[wearing_title_id])

class Title(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(20), default="#007bff")
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    
    # 关系定义
    users = db.relationship('User', secondary=user_titles, back_populates='titles')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    
    # 关系定义
    posts = db.relationship('Post', back_populates='category')

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    color = db.Column(db.String(20), default="#6c757d")
    
    # 关系定义
    posts = db.relationship('Post', secondary=post_tags, back_populates='tags')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    featured_image = db.Column(db.String(120))
    summary = db.Column(db.String(200))
    views = db.Column(db.Integer, default=0)
    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # 外键
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    
    # 关系定义
    author = db.relationship('User', back_populates='posts', foreign_keys=[author_id])
    category = db.relationship('Category', back_populates='posts')
    comments = db.relationship('Comment', back_populates='post', lazy=True, cascade='all, delete-orphan')
    tags = db.relationship('Tag', secondary=post_tags, back_populates='posts')
    liking_users = db.relationship('User', secondary=post_likes, back_populates='liked_posts')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    approved = db.Column(db.Boolean, default=False)
    
    # 外键
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    
    # 关系定义
    post = db.relationship('Post', back_populates='comments')
    author = db.relationship('User', back_populates='comments')
    replies = db.relationship('Comment', back_populates='parent', foreign_keys=[parent_id])
    parent = db.relationship('Comment', back_populates='replies', remote_side=[id], foreign_keys=[parent_id])

def import_data_from_old_db():
    """从旧数据库导入数据到新数据库"""
    # 这里实现数据迁移逻辑
    print("数据迁移功能尚未实现")
    pass

def create_tables():
    """创建所有数据库表"""
    with app.app_context():
        db.create_all()
        print("已创建所有数据库表")

if __name__ == "__main__":
    create_tables()
    # import_data_from_old_db()  # 取消注释以导入旧数据 