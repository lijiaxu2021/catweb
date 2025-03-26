from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SubmitField, SelectField, BooleanField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from functools import wraps
from slugify import slugify

# 处理UTC时区 - 兼容Python 3.10和3.11+
try:
    # Python 3.11+ 方式
    from datetime import UTC
except ImportError:
    # Python 3.10 及更早版本的兼容方式
    from datetime import timezone
    UTC = timezone.utc

from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError
from flask_ckeditor import CKEditor, CKEditorField
import os
from werkzeug.utils import secure_filename
import re
import unicodedata
from sqlalchemy.sql import func
from PIL import Image
from markupsafe import Markup
from sqlalchemy.sql import and_, or_
import time
from bs4 import BeautifulSoup
import random
import logging
from logging.handlers import RotatingFileHandler
from sqlalchemy import event
import psutil
import platform
import socket
import subprocess
import json
import pytz
from urllib.parse import urlparse, urljoin

# 定义缺失的东八区时区常量和获取函数
# 添加在文件顶部导入之后
# 定义东八区时区
# CHINA_TIMEZONE = pytz.timezone('Asia/Shanghai')

# 获取当前东八区时间的辅助函数
# def get_china_time():
#     return datetime.now(pytz.UTC).astimezone(CHINA_TIMEZONE)

app = Flask(__name__)

# 获取项目根目录
basedir = os.path.abspath(os.path.dirname(__file__))

# 配置SQLite数据库路径
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'blog.db')
app.config['SECRET_KEY'] = 'your-secret-key'  # 设置一个安全的密钥
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 最大上传限制
app.config['CKEDITOR_PKG_TYPE'] = 'full'  # 使用完整版本
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 800
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'
app.config['CKEDITOR_ENABLE_CSRF'] = True
app.config['CKEDITOR_IMAGE_UPLOADER'] = True
app.config['CKEDITOR_ENABLE_CODESNIPPET'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 设置会话过期时间,例如7天

# 添加所有可用的插件
app.config['CKEDITOR_EXTRA_PLUGINS'] = [
    'image', 'uploadimage', 'justify', 'colorbutton', 
    'find', 'templates', 'table', 'div', 'font', 
    'smiley', 'specialchar', 'iframe', 'codesnippet',
    'link', 'list', 'basicstyles', 'format', 'horizontalrule',
    'maximize', 'pagebreak', 'preview', 'scayt', 'showblocks',
    'sourcearea', 'stylescombo', 'tab', 'toolbar', 'undo', 'wysiwygarea',
    'a11yhelp', 'about', 'bidi', 'blockquote', 'clipboard', 'dialogadvtab',
    'elementspath', 'enterkey', 'entities', 'filebrowser', 'floatingspace',
    'htmlwriter', 'indentblock', 'indentlist', 'language', 'magicline',
    'liststyle', 'newpage', 'panelbutton', 'pastefromword', 'pastetext',
    'removeformat', 'save', 'selectall', 'sharedspace', 'showborders'
]
app.config['CKEDITOR_UPLOAD_ERROR_MESSAGE'] = '上传失败!'

# 初始化扩展
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF令牌有效期（秒）
app.config['WTF_CSRF_SSL_STRICT'] = False  # 如果不是HTTPS环境，设为False
ckeditor = CKEditor(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'
login_manager.login_message_category = 'info'

# 配置Flask日志
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/flask.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('博客应用启动')

# 添加自定义的 csrf_exempt 装饰器
def csrf_exempt(view):
    """标记一个视图为CSRF豁免"""
    view.csrf_exempt = True
    return view

# 文章标签关联表（多对多关系）
post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

# 用户称号模型
class Title(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(20), default="#007bff")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 建立与用户的多对多关系
    users = db.relationship('User', secondary='user_titles', back_populates='titles')
    
    def __repr__(self):
        return f'<Title {self.name}>'

# 用户-称号关联表（多对多）
user_titles = db.Table('user_titles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('title_id', db.Integer, db.ForeignKey('title.id'), primary_key=True),
    db.Column('granted_at', db.DateTime, default=datetime.utcnow)
)

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    profile_pic = db.Column(db.String(120), default='default_profile.jpg')
    bio = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    titles = db.relationship('Title', secondary='user_titles', back_populates='users')
    
    # 添加当前佩戴的称号ID
    wearing_title_id = db.Column(db.Integer, db.ForeignKey('title.id'), nullable=True)
    wearing_title = db.relationship('Title', foreign_keys=[wearing_title_id])

    def __repr__(self):
        return f'<User {self.username}>'

    def get_total_likes(self):
        # 查询用户所有文章获得的点赞总数
        return Like.query.join(Post).filter(Post.author_id == self.id).count()

    def check_password(self, password):
        return check_password_hash(self.password, password)

# 分类模型
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    posts = db.relationship('Post', backref='category', lazy=True)

    def __repr__(self):
        return f'<Category {self.name}>'

# 标签模型
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    color = db.Column(db.String(20), default="#6c757d")  # 默认颜色

    @property
    def random_color(self):
        # 生成一个随机的浅色调
        colors = [
            "#6610f2", "#6f42c1", "#e83e8c", "#fd7e14", "#28a745",
            "#20c997", "#17a2b8", "#dc3545", "#ffc107", "#007bff"
        ]
        return random.choice(colors)

    def __repr__(self):
        return f'<Tag {self.name}>'

# 文章模型
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    featured_image = db.Column(db.String(120))
    summary = db.Column(db.String(200))
    views = db.Column(db.Integer, default=0)
    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    tags = db.relationship('Tag', secondary=post_tags, backref=db.backref('posts', lazy='dynamic'))

    def __repr__(self):
        return f'<Post {self.title}>'

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)
    return decorated_view
# 评论模型
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)

    def __repr__(self):
        return f'<Comment {self.id}>'

# 网站设置模型
class SiteSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Text)
    
    def __repr__(self):
        return f"<Setting {self.key}>"

# 文章表单
class PostForm(FlaskForm):
    title = StringField('标题', validators=[DataRequired(), Length(min=3, max=100)])
    summary = TextAreaField('摘要', validators=[Length(max=200)])
    content = CKEditorField('内容', validators=[DataRequired()])
    category_id = SelectField('分类', coerce=int, validators=[DataRequired()])
    tags = StringField('标签 (用逗号分隔)')
    published = BooleanField('发布')
    submit = SubmitField('保存')

# 登录表单
class LoginForm(FlaskForm):
    username = StringField('用户名或邮箱', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    remember = BooleanField('记住我')
    submit = SubmitField('登录')

# 注册表单
class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=2, max=20)])
    # 将Optional()替换为不使用任何验证器
    email = StringField('邮箱（选填）', validators=[Email()])  # 如果为空则不会验证Email格式
    # 或者
    # email = StringField('邮箱（选填）')  # 完全不验证
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('注册')
    
    # 更新自定义验证函数
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('该用户名已被使用，请选择其他用户名')
    
    # 在validate_email中处理可选性
    def validate_email(self, email):
        # 仅当邮箱不为空时才验证唯一性
        if email.data and email.data.strip():
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('该邮箱已被注册，请使用其他邮箱')

# 用户加载器
@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        # 在用户对象中添加称号信息
        user.all_titles = user.titles
        user.wearing_title = user.wearing_title
    return user

# 自定义slugify函数
def slugify(text):
    text = str(text)
    text = unicodedata.normalize('NFKD', text)
    text = re.sub(r'[^\w\s-]', '', text.lower())
    text = re.sub(r'[-\s]+', '-', text).strip('-_')
    return text

# 添加这个函数定义（在其他函数定义之前，例如在 app 配置之后）
def strip_tags(html_content):
    """从HTML内容中移除所有标签"""
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, "html.parser")
    return soup.get_text()

# 首页
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(published=True).order_by(Post.created_at.desc()).paginate(page=page, per_page=5)
    recent_posts = Post.query.filter_by(published=True).order_by(Post.created_at.desc()).limit(5).all()
    categories = Category.query.all()
    popular_tags = Tag.query.all()[:10] 
    return render_template('index.html', 
                          posts=posts, 
                          recent_posts=recent_posts, 
                          categories=categories, 
                          popular_tags=popular_tags)

# 登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('无效的用户名或密码', 'danger')
    
    return render_template('login.html', form=form)

# 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功退出登录', 'success')
    return redirect(url_for('index'))

# 文章详情页面
@app.route('/post/<slug>')
def post(slug):
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    # 增加浏览量
    post.views += 1
    db.session.commit()
    
    comments = Comment.query.filter_by(post_id=post.id, approved=True, parent_id=None).all()
    
    # 获取点赞数
    likes_count = Like.query.filter_by(post_id=post.id).count()
    # 如果用户已登录，检查是否已点赞
    is_liked = False
    if current_user.is_authenticated:
        is_liked = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first() is not None
    
    return render_template('post.html', post=post, comments=comments, likes_count=likes_count, is_liked=is_liked)

# 管理员面板
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    post_count = Post.query.count()
    user_count = User.query.count()
    comment_count = Comment.query.count()
    category_count = Category.query.count()
    tag_count = Tag.query.count()
    
    recent_posts = Post.query.order_by(Post.created_at.desc()).limit(5).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_comments = Comment.query.order_by(Comment.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         post_count=post_count,
                         user_count=user_count,
                         comment_count=comment_count,
                         category_count=category_count,
                         tag_count=tag_count,
                         recent_posts=recent_posts,
                         recent_users=recent_users,
                         recent_comments=recent_comments)

# 添加分类页面路由
@app.route('/category/<string:slug>')
def category(slug):
    category = Category.query.filter_by(slug=slug).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(category_id=category.id, published=True).order_by(Post.created_at.desc()).paginate(
        page=page, per_page=5)
    return render_template('category.html', category=category, posts=posts)

# 添加标签页面路由
@app.route('/tag/<slug>')
def tag(slug):
    tag = Tag.query.filter_by(slug=slug).first_or_404()
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '')
    
    # 基本查询 - 获取包含该标签的所有文章
    query = Post.query.filter(Post.tags.contains(tag)).filter(Post.published == True)
    
    # 如果有搜索条件，添加搜索过滤
    if search_query:
        search_terms = '%' + search_query + '%'
        query = query.filter(or_(
            Post.title.ilike(search_terms),
            Post.content.ilike(search_terms),
            Post.summary.ilike(search_terms)
        ))
    
    # 按时间倒序排序并分页
    posts = query.order_by(Post.created_at.desc()).paginate(page=page, per_page=10)
    
    return render_template('tag.html', tag=tag, posts=posts, search_query=search_query)

# 添加关于页面
@app.route('/about')
def about():
    return render_template('about.html')

# 修改搜索建议API以支持不同类型
@app.route('/api/search-suggestions')
def search_suggestions():
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'post')  # 默认搜索文章
    
    if not query or len(query) < 2:
        return jsonify({'suggestions': []})
    
    suggestions = []
    
    if search_type == 'user':
        # 搜索用户
        users = User.query.filter(User.username.ilike(f'%{query}%')).limit(5).all()
        for user in users:
            suggestions.append({
                'id': user.id,
                'text': user.username,
                'type': 'user',
                'image': url_for('static', filename=f'uploads/{user.profile_pic}')
            })
    else:
        # 搜索文章
        posts = Post.query.filter(
            or_(
                Post.title.ilike(f'%{query}%'),
                Post.content.ilike(f'%{query}%')
            ),
            Post.published == True
        ).limit(5).all()
        
        for post in posts:
            suggestions.append({
                'id': post.id,
                'text': post.title,
                'type': 'post'
            })
    
    return jsonify({'suggestions': suggestions})

# 文章搜索匹配度计算函数
def calculate_relevance_score(title, content, query):
    """计算文章与搜索词的相关度分数"""
    # 将查询拆分为关键词
    keywords = query.lower().split()
    score = 0
    
    # 标题匹配权重（标题匹配比内容匹配更重要）
    title_weight = 3.0
    content_weight = 1.0
    
    # 计算标题匹配分数
    title_score = 0
    title_lower = title.lower()
    for keyword in keywords:
        # 如果关键词在标题中出现
        if keyword in title_lower:
            # 计算出现次数
            occurrences = title_lower.count(keyword)
            # 加权计算
            title_score += occurrences * len(keyword) * title_weight
    
    # 计算内容匹配分数
    content_score = 0
    if content:
        # 去除HTML标签后的纯文本内容
        plain_content = BeautifulSoup(content, "html.parser").get_text().lower()
        for keyword in keywords:
            # 如果关键词在内容中出现
            if keyword in plain_content:
                # 计算出现次数
                occurrences = plain_content.count(keyword)
                # 加权计算
                content_score += occurrences * len(keyword) * content_weight
    
    # 总分数是标题分数和内容分数的总和
    score = title_score + content_score
    
    # 标准化分数（0-100）
    max_possible_score = sum(len(keyword) * title_weight * 3 for keyword in keywords) + \
                        sum(len(keyword) * content_weight * 10 for keyword in keywords)
    
    if max_possible_score > 0:
        normalized_score = min(100, (score / max_possible_score) * 100)
    else:
        normalized_score = 0
    
    return normalized_score

# 修改搜索路由以支持匹配度排序
@app.route('/search')
def search():
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'post')
    page = request.args.get('page', 1, type=int)
    
    if not query:
        return redirect(url_for('index'))
    
    # 记录搜索开始时间
    start_time = time.time()
    
    if search_type == 'user':
        # 用户搜索
        users = User.query.filter(User.username.ilike(f'%{query}%')).paginate(
            page=page, per_page=10
        )
        # 计算搜索用时
        search_time = time.time() - start_time
        return render_template('search_users.html', users=users, query=query, search_time=search_time)
    else:
        # 文章搜索 - 基本查询
        base_query = Post.query.filter(
            or_(
                Post.title.ilike(f'%{query}%'),
                Post.content.ilike(f'%{query}%')
            ),
            Post.published == True
        )
        
        # 获取所有匹配的文章
        all_matching_posts = base_query.all()
        
        # 计算每篇文章的相关度分数
        scored_posts = []
        for post in all_matching_posts:
            relevance_score = calculate_relevance_score(post.title, post.content, query)
            scored_posts.append((post, relevance_score))
        
        # 按相关度分数降序排序
        scored_posts.sort(key=lambda x: x[1], reverse=True)
        
        # 手动分页
        total = len(scored_posts)
        per_page = 10
        offset = (page - 1) * per_page
        current_page_posts = scored_posts[offset:offset+per_page]
        
        # 创建简单的分页对象
        class SimplePagination:
            def __init__(self, items, page, per_page, total):
                self.items = items
                self.page = page
                self.per_page = per_page
                self.total = total
                self.pages = (total + per_page - 1) // per_page
            
            @property
            def has_prev(self):
                return self.page > 1
            
            @property
            def has_next(self):
                return self.page < self.pages
            
            @property
            def prev_num(self):
                return self.page - 1
            
            @property
            def next_num(self):
                return self.page + 1
            
            def iter_pages(self, left_edge=2, left_current=2, right_current=5, right_edge=2):
                last = 0
                for num in range(1, self.pages + 1):
                    if num <= left_edge or \
                       (num > self.page - left_current - 1 and num < self.page + right_current) or \
                       num > self.pages - right_edge:
                        if last + 1 != num:
                            yield None
                        yield num
                        last = num
        
        # 创建分页对象
        pagination = SimplePagination(
            items=[p[0] for p in current_page_posts],
            page=page,
            per_page=per_page,
            total=total
        )
        
        # 计算搜索用时
        search_time = time.time() - start_time
        
        # 渲染模板，传递带有相关度分数的结果
        return render_template(
            'search.html', 
            posts=pagination, 
            query=query, 
            search_time=search_time,
            scored_posts=current_page_posts  # 包含分数的文章列表
        )

# 订阅功能
@app.route('/subscribe', methods=['POST'])
def subscribe():
    # 这里可以添加实际的邮件订阅逻辑
    flash('感谢您的订阅！', 'success')
    return redirect(url_for('index'))

# 管理文章列表
@app.route('/admin/posts')
@login_required
def admin_posts():
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/posts.html', posts=posts)

# 管理评论
@app.route('/admin/comments')
@login_required
def admin_comments():
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    comments = Comment.query.order_by(Comment.created_at.desc()).all()
    return render_template('admin/comments.html', comments=comments)

# 管理分类
@app.route('/admin/categories', methods=['GET', 'POST'])
@login_required
def admin_categories():
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    categories = Category.query.all()
    
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('分类名称不能为空', 'danger')
        else:
            slug = slugify(name)
            # 检查是否已存在
            if Category.query.filter((Category.name == name) | (Category.slug == slug)).first():
                flash('该分类已存在', 'danger')
            else:
                category = Category(name=name, slug=slug)
                db.session.add(category)
                db.session.commit()
                flash('分类添加成功', 'success')
                return redirect(url_for('admin_categories'))
    
    return render_template('admin/categories.html', categories=categories)

# 删除分类
@app.route('/admin/category/<int:id>/delete', methods=['POST'])
@login_required
def admin_delete_category(id):
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    category = Category.query.get_or_404(id)
    
    # 检查是否有文章使用该分类
    if Post.query.filter_by(category_id=id).first():
        flash('无法删除分类，还有文章使用该分类', 'danger')
        return redirect(url_for('admin_categories'))
    
    db.session.delete(category)
    db.session.commit()
    flash('分类已删除', 'success')
    return redirect(url_for('admin_categories'))

# 管理标签
@app.route('/admin/tags', methods=['GET', 'POST'])
@login_required
def manage_tags():
    if not current_user.is_admin:
        flash('只有管理员可以管理标签', 'danger')
        return redirect(url_for('index'))
    
    # 处理标签添加
    if request.method == 'POST':
        tag_name = request.form.get('name')
        color = request.form.get('color', '#6c757d')  # 默认颜色
        
        if not tag_name:
            flash('标签名称不能为空', 'warning')
        else:
            # 检查标签是否已存在
            existing_tag = Tag.query.filter_by(name=tag_name).first()
            if existing_tag:
                flash(f'标签 "{tag_name}" 已存在', 'warning')
            else:
                # 创建新标签
                slug = slugify(tag_name)
                tag = Tag(name=tag_name, slug=slug, color=color)
                db.session.add(tag)
                try:
                    db.session.commit()
                    flash(f'已成功添加标签 "{tag_name}"', 'success')
                    # 记录标签创建
                    log_activity('database', 'create_tag', f'创建了标签: {tag_name}', current_user.id)
                except Exception as e:
                    db.session.rollback()
                    flash(f'添加标签失败: {str(e)}', 'danger')
    
    # 获取所有标签
    tags = Tag.query.order_by(Tag.name).all()
    return render_template('admin/tags.html', tags=tags)

# 删除标签
@app.route('/admin/tag/<int:id>/delete', methods=['POST'])
@login_required
def admin_delete_tag(id):
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    tag = Tag.query.get_or_404(id)
    
    db.session.delete(tag)
    db.session.commit()
    flash('标签已删除', 'success')
    return redirect(url_for('admin_tags'))

# 管理用户
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

# 切换用户管理员状态
@app.route('/admin/user/<int:id>/toggle-admin', methods=['POST'])
@login_required
def admin_toggle_user_admin(id):
    if not current_user.is_admin:
        flash('只有管理员可以访问后台管理', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(id)
    
    # 防止取消自己的管理员权限
    if user.id == current_user.id:
        flash('不能修改自己的管理员状态', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    flash(f'用户 {user.username} 的管理员状态已更新', 'success')
    return redirect(url_for('admin_users'))

# 管理系统设置
@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if not current_user.is_admin:
        flash('您没有权限访问此页面', 'danger')
        return redirect(url_for('index'))
    
    background_image = SiteSetting.query.filter_by(key='background_image').first()
    
    if request.method == 'POST':
        # 处理其他设置...
        
        # 处理背景图片上传
        if 'background_image' in request.files and request.files['background_image'].filename:
            background_file = request.files['background_image']
            if background_file and allowed_file(background_file.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                # 确保背景目录存在
                bg_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'background')
                if not os.path.exists(bg_dir):
                    os.makedirs(bg_dir)
                
                # 删除旧背景图片
                if background_image and background_image.value:
                    old_file = os.path.join(bg_dir, background_image.value)
                    if os.path.exists(old_file):
                        os.remove(old_file)
                
                # 保存新背景图片
                filename = secure_filename(background_file.filename)
                filename = f"bg_{int(time.time())}_{filename}"  # 添加时间戳避免重名
                background_file.save(os.path.join(bg_dir, filename))
                
                # 更新设置
                if background_image:
                    background_image.value = filename
                else:
                    background_image = SiteSetting(key='background_image', value=filename)
                    db.session.add(background_image)
                
                db.session.commit()
                flash('背景图片已更新', 'success')
        
        return redirect(url_for('admin_settings'))
    
    # 获取当前背景图片
    background_image_value = background_image.value if background_image else None
    
    return render_template('admin/settings.html', 
                          background_image=background_image_value)

# 添加注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # 生成安全的密码哈希
        hashed_password = generate_password_hash(form.password.data)
        
        # 创建新用户 - 邮箱可以为空
        user = User(
            username=form.username.data,
            email=form.email.data if form.email.data else None,
            password=hashed_password
        )
        
        db.session.add(user)
        db.session.commit()
        
        # 记录注册事件，用于触发注册消息
        session['registration_event_time'] = datetime.now().timestamp()
        
        flash('注册成功！您现在可以登录了', 'success')
        login_user(user)
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# 添加忘记密码功能
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # 简单实现，实际应用中应该发送重置链接到邮箱
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # 在实际应用中，这里应该生成一个唯一的令牌并发送重置链接到用户邮箱
            flash('密码重置链接已发送到您的邮箱，请查收', 'success')
        else:
            flash('未找到该邮箱对应的账户', 'danger')
            
    return render_template('forgot_password.html')

# 将所有标准错误代码转到自定义错误页面
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

def create_initial_data():
    if not User.query.first():
        admin = User(
            username='lijiaxu',
            email='admin@example.com',
            password=generate_password_hash('lijiaxu2011'),
            is_admin=True
        )
        db.session.add(admin)
        
        # 创建默认分类
        categories = ['技术', '生活', '随想', '教程']
        for cat_name in categories:
            category = Category(name=cat_name, slug=slugify(cat_name))
            db.session.add(category)
            
        # 创建默认标签
        tags = ['Python', 'Flask', 'Web开发', '前端', '后端']
        for tag_name in tags:
            tag = Tag(name=tag_name, slug=slugify(tag_name))
            db.session.add(tag)
            
        db.session.commit()

# 用户个人资料
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = None  # 这里可以创建一个ProfileForm用于编辑个人资料
    if request.method == 'POST':
        # 处理个人资料更新逻辑
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                current_user.profile_pic = filename
        
        current_user.username = request.form.get('username', current_user.username)
        current_user.email = request.form.get('email', current_user.email)
        current_user.bio = request.form.get('bio', current_user.bio)
        
        db.session.commit()
        flash('个人资料已更新', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user)

# 我的文章
@app.route('/my-posts')
@login_required
def my_posts():
    posts = Post.query.filter_by(author_id=current_user.id).order_by(Post.created_at.desc()).all()
    return render_template('my_posts.html', posts=posts)

# 创建新文章
@app.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        # 处理标签
        tag_names = [t.strip() for t in form.tags.data.split(',') if t.strip()]
        post_tags = []
        for tag_name in tag_names:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name, slug=slugify(tag_name))
                db.session.add(tag)
            post_tags.append(tag)
            
        # 处理特色图片
        featured_image = 'default_post.jpg'
        if 'featured_image' in request.files:
            file = request.files['featured_image']
            if file and file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                featured_image = filename
                
        # 创建文章
        slug = slugify(form.title.data)
        # 检查slug是否已存在
        if Post.query.filter_by(slug=slug).first():
            slug = f"{slug}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
        post = Post(
            title=form.title.data,
            slug=slug,
            content=form.content.data,
            summary=form.summary.data or form.content.data[:150] + '...',
            featured_image=featured_image,
            published=form.published.data,
            author_id=current_user.id,
            category_id=form.category_id.data
        )
        
        # 添加标签
        for tag in post_tags:
            post.tags.append(tag)
            
        db.session.add(post)
        db.session.commit()
        
        flash('文章创建成功！', 'success')
        return redirect(url_for('post', slug=post.slug))
    
    return render_template('create_post.html', form=form)

# 编辑文章
@app.route('/edit-post/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Post.query.get_or_404(id)
    
    # 检查是否是作者或管理员
    if post.author_id != current_user.id and not current_user.is_admin:
        flash('您没有权限编辑该文章', 'danger')
        return redirect(url_for('index'))
    
    form = PostForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        # 处理标签
        tag_names = [t.strip() for t in form.tags.data.split(',') if t.strip()]
        post_tags = []
        for tag_name in tag_names:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name, slug=slugify(tag_name))
                db.session.add(tag)
            post_tags.append(tag)
        
        # 处理特色图片
        if 'featured_image' in request.files:
            file = request.files['featured_image']
            if file and file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                post.featured_image = filename
        
        # 更新文章
        post.title = form.title.data
        post.content = form.content.data
        post.summary = form.summary.data or form.content.data[:150] + '...'
        post.published = form.published.data
        post.category_id = form.category_id.data
        
        # 更新标签
        post.tags = []
        for tag in post_tags:
            post.tags.append(tag)
        
        db.session.commit()
        flash('文章更新成功！', 'success')
        return redirect(url_for('post', slug=post.slug))
    
    # GET请求，填充表单
    form.title.data = post.title
    form.content.data = post.content
    form.summary.data = post.summary
    form.published.data = post.published
    form.category_id.data = post.category_id
    form.tags.data = ', '.join([tag.name for tag in post.tags])
    
    return render_template('edit_post.html', form=form, post=post)

# 删除文章
@app.route('/delete-post/<int:id>')
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)
    
    # 检查是否是作者或管理员
    if post.author_id != current_user.id and not current_user.is_admin:
        flash('您没有权限删除该文章', 'danger')
        return redirect(url_for('index'))
    
    db.session.delete(post)
    db.session.commit()
    flash('文章已删除', 'success')
    
    # 如果是从管理页面删除，返回管理页面
    if request.referrer and 'admin' in request.referrer:
        return redirect(url_for('admin_posts'))
    
    return redirect(url_for('my_posts'))

# 添加评论
@app.route('/post/<string:slug>/comment', methods=['POST'])
@login_required
def add_comment(slug):
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            comment = Comment(content=content, post_id=post.id, user_id=current_user.id)
            db.session.add(comment)
            db.session.commit()
            
            # 记录日志
            log = Log(
                type='article',
                action='add_comment',
                message=f'用户 {current_user.username} 在文章 "{post.title}" 下发表评论',
                user_id=current_user.id,
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('评论已发布', 'success')
            
            # 发送通知给文章作者
            if post.author.id != current_user.id:
                notify_message = Message(
                    title="您的文章收到了新评论",
                    content=f'{current_user.username} 在您的文章 <a href="{url_for("post", slug=post.slug)}">{post.title}</a> 下发表了评论。',
                    user_id=post.author.id,
                    type="info",
                    icon="fas fa-comment"
                )
                db.session.add(notify_message)
                db.session.commit()
        
        return redirect(url_for('post', slug=post.slug))

# 删除评论
@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # 检查是否是评论作者或管理员
    if comment.user_id != current_user.id and not current_user.is_admin:
        flash('您没有权限删除此评论', 'danger')
        return redirect(url_for('post', slug=comment.post.slug))
    
    db.session.delete(comment)
    db.session.commit()
    
    flash('评论已删除', 'success')
    return redirect(url_for('post', slug=comment.post.slug))

# 添加CSRF令牌到模板上下文
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=lambda: '<input type="hidden" name="csrf_token" value="{0}">'.format(generate_csrf()))

# 修改上传处理路由以更好地处理错误情况
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    """处理CKEditor和自定义图片上传"""
    try:
        print("上传请求开始处理...")
        print(f"请求方法: {request.method}")
        print(f"Content-Type: {request.headers.get('Content-Type')}")
        print(f"请求文件: {list(request.files.keys())}")
        print(f"请求表单数据: {list(request.form.keys())}")
        
        # 检查是否有文件被上传
        if 'upload' not in request.files and 'file' not in request.files:
            print("错误: 没有找到文件")
            return jsonify({'uploaded': 0, 'error': {'message': '没有找到文件'}})
        
        # 获取上传的文件
        file = request.files.get('upload') or request.files.get('file')
        print(f"文件名: {file.filename if file else 'None'}")
        
        if not file or file.filename == '':
            print("错误: 没有选择文件")
            return jsonify({'uploaded': 0, 'error': {'message': '没有选择文件'}})
        
        # 确保文件类型安全
        if not file.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
            print(f"错误: 不支持的文件类型: {file.filename}")
            return jsonify({'uploaded': 0, 'error': {'message': '仅支持JPG、PNG和GIF格式'}})
        
        # 创建安全的文件名并保存文件
        filename = f"user{current_user.id}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        print(f"保存文件到: {filepath}")
        file.save(filepath)
        
        # 返回URL
        url = url_for('static', filename=f'uploads/{filename}')
        print(f"生成URL: {url}")
        
        # 处理CKEditor回调
        callback = request.args.get('CKEditorFuncNum')
        if callback:
            print(f"使用CKEditor回调: {callback}")
            response_html = f"""
            <script>
                window.parent.CKEDITOR.tools.callFunction({callback}, '{url}');
            </script>
            """
            return response_html
        
        # 返回标准JSON响应
        print("返回JSON响应")
        return jsonify({
            'uploaded': 1, 
            'fileName': filename, 
            'url': url
        })
        
    except Exception as e:
        # 记录错误并返回友好的错误消息
        print(f"上传错误: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'uploaded': 0, 'error': {'message': f'上传失败: {str(e)}'}})

# 检查文件是否允许上传
def allowed_file(filename, allowed_extensions=None):
    """检查文件是否有允许的扩展名"""
    if allowed_extensions is None:
        # 默认允许的扩展名
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# 添加文件浏览器路由
@app.route('/files')
@login_required
def browse_files():
    files = []
    upload_folder = app.config['UPLOAD_FOLDER']
    
    # 获取上传目录中的图片文件
    if os.path.exists(upload_folder):
        for filename in os.listdir(upload_folder):
            if allowed_file(filename):
                file_url = url_for('static', filename=f'uploads/{filename}')
                file_size = os.path.getsize(os.path.join(upload_folder, filename)) // 1024  # KB
                files.append({
                    'name': filename,
                    'url': file_url,
                    'size': f"{file_size} KB"
                })
    
    # 返回CKEditor可识别的文件浏览器响应
    return render_template('files_browser.html', files=files)

# 修改图片上传路由以处理CSRF
@app.route('/editor-upload', methods=['POST'])
@login_required
@csrf.exempt
def editor_upload():
    """简化的图片上传处理"""
    try:
        print("编辑器上传开始...")
        # 不需要显式检查CSRF令牌，Flask-WTF会自动处理
        
        if 'upload' not in request.files:
            print("没有找到上传文件")
            return jsonify({'uploaded': 0, 'error': {'message': '没有文件被上传'}})
        
        file = request.files['upload']
        if file.filename == '':
            print("文件名为空")
            return jsonify({'uploaded': 0, 'error': {'message': '未选择文件'}})
        
        if not file.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
            print(f"不支持的文件类型: {file.filename}")
            return jsonify({'uploaded': 0, 'error': {'message': '仅支持JPG、PNG和GIF格式'}})
        
        # 保存文件
        filename = f"editor-{current_user.id}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # 返回URL
        url = url_for('static', filename=f'uploads/{filename}')
        print(f"上传成功，URL: {url}")
        return jsonify({'uploaded': 1, 'fileName': filename, 'url': url})
    
    except Exception as e:
        print(f"编辑器上传错误: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'uploaded': 0, 'error': {'message': f'上传失败: {str(e)}'}})

# 获取用户已上传图片列表的路由
@app.route('/my-images')
@login_required
def my_images():
    """获取当前用户上传的图片列表"""
    images = []
    upload_folder = app.config['UPLOAD_FOLDER']
    
    if os.path.exists(upload_folder):
        # 只获取当前用户的图片
        user_prefix = f"user{current_user.id}-"
        editor_prefix = f"editor-{current_user.id}-"
        
        for filename in os.listdir(upload_folder):
            # 检查是否为用户上传的图片
            if (filename.startswith(user_prefix) or filename.startswith(editor_prefix)) and allowed_file(filename):
                file_url = url_for('static', filename=f'uploads/{filename}')
                file_date = datetime.fromtimestamp(os.path.getctime(os.path.join(upload_folder, filename))).strftime('%Y-%m-%d %H:%M')
                
                # 尝试获取图片尺寸
                try:
                    img_path = os.path.join(upload_folder, filename)
                    with Image.open(img_path) as img:
                        width, height = img.size
                        dimensions = f"{width}x{height}"
                except:
                    dimensions = "未知"
                
                images.append({
                    'url': file_url,
                    'name': filename,
                    'date': file_date,
                    'dimensions': dimensions
                })
    
    # 按照上传日期倒序排序
    images.sort(key=lambda x: x['date'], reverse=True)
    return jsonify({'images': images})

# 添加重置密码功能
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.email:  # 确认用户存在且有邮箱
            # 发送密码重置邮件...
            flash('重置密码的邮件已发送，请查收', 'info')
            return redirect(url_for('login'))
        else:
            flash('未找到该邮箱关联的账户或账户未设置邮箱', 'danger')
            
    return render_template('reset_password_request.html', form=form)

# 删除背景图片的路由（禁用CSRF保护）
@app.route('/admin/delete-background', methods=['POST'])
@login_required
@csrf.exempt
def delete_background():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': '没有权限'})
    
    background_setting = SiteSetting.query.filter_by(key='background_image').first()
    
    if background_setting and background_setting.value:
        # 删除文件
        bg_path = os.path.join(app.config['UPLOAD_FOLDER'], 'background', background_setting.value)
        if os.path.exists(bg_path):
            os.remove(bg_path)
        
        # 清除设置
        background_setting.value = None
        db.session.commit()
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': '背景图片不存在'})

# 添加背景图片管理功能
@app.context_processor
def inject_settings():
    """向所有模板注入全局设置"""
    settings = {}
    
    # 获取背景图片设置
    background_image = SiteSetting.query.filter_by(key='background_image').first()
    if background_image and background_image.value:
        settings['background_image'] = background_image.value
    
    return settings

# 用户主页
@app.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    # 获取用户发布的文章，按发布时间倒序排列
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(author_id=user.id, published=True) \
        .order_by(Post.created_at.desc()) \
        .paginate(page=page, per_page=5)
    
    # 获取用户文章总数和评论总数
    post_count = Post.query.filter_by(author_id=user.id, published=True).count()
    comment_count = Comment.query.join(Post).filter(Post.author_id == user.id).count()
    
    # 获取用户获赞总数
    like_count = user.get_total_likes()
    
    # 获取用户最常使用的标签
    user_tags_query = db.session.query(
        Tag.id, Tag.name, Tag.slug, db.func.count(post_tags.c.tag_id).label('count')
    ).join(post_tags).join(Post).filter(
        Post.author_id == user.id,
        Post.published == True
    ).group_by(Tag.id).order_by(db.desc('count')).limit(5)
    
    user_tags = user_tags_query.all()
    
    return render_template(
        'user_profile.html', 
        user=user, 
        posts=posts,
        post_count=post_count,
        comment_count=comment_count,
        like_count=like_count,
        user_tags=user_tags
    )

# 个人资料编辑表单
class ProfileForm(FlaskForm):
    email = StringField('邮箱', validators=[Optional(), Email()])
    bio = TextAreaField('个人简介', validators=[Optional(), Length(max=200)])
    profile_pic = FileField('头像', validators=[Optional()])
    submit = SubmitField('保存修改')

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileForm()
    
    if form.validate_on_submit():
        if form.email.data:
            # 检查邮箱是否已被其他用户使用
            email_user = User.query.filter_by(email=form.email.data).first()
            if email_user and email_user.id != current_user.id:
                flash('该邮箱已被其他用户使用', 'danger')
                return redirect(url_for('edit_profile'))
            
            current_user.email = form.email.data
        
        if form.bio.data:
            current_user.bio = form.bio.data
        
        # 处理头像上传
        if form.profile_pic.data:
            file = form.profile_pic.data
            if file and allowed_file(file.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                filename = secure_filename(file.filename)
                filename = f"avatar_{current_user.id}_{int(time.time())}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                # 删除旧头像（如果不是默认头像）
                if current_user.profile_pic != 'default_profile.jpg':
                    old_avatar = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_pic)
                    if os.path.exists(old_avatar):
                        os.remove(old_avatar)
                
                current_user.profile_pic = filename
        
        db.session.commit()
        flash('个人资料已更新', 'success')
        return redirect(url_for('user_profile', username=current_user.username))
    
    # 预填表单字段
    if request.method == 'GET':
        form.email.data = current_user.email
        form.bio.data = current_user.bio
    
    return render_template('edit_profile.html', form=form)

# 自定义过滤器：高亮搜索词
@app.template_filter('highlight')
def highlight_filter(text, search):
    if not search or not text:
        return Markup(text)
    text = str(text)
    search = re.escape(search)
    highlighted = re.sub(f'({search})', r'<mark>\1</mark>', text, flags=re.IGNORECASE)
    return Markup(highlighted)

# 点赞模型
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 确保一个用户对一篇文章只能点赞一次
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)
    
    user = db.relationship('User', backref=db.backref('likes', lazy='dynamic'))
    post = db.relationship('Post', backref=db.backref('likes', lazy='dynamic'))

# 点赞状态API
@app.route('/api/like-status/<int:post_id>')
def like_status(post_id):
    post = Post.query.get_or_404(post_id)
    likes_count = Like.query.filter_by(post_id=post.id).count()
    
    # 检查用户是否已点赞
    is_liked = False
    if current_user.is_authenticated:
        is_liked = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first() is not None
    
    return jsonify({'likes': likes_count, 'is_liked': is_liked})

# 点赞/取消点赞API
@app.route('/api/like/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # 检查是否已点赞
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    
    if existing_like:
        # 已点赞，则取消点赞
        db.session.delete(existing_like)
        db.session.commit()
        action = 'unliked'
    else:
        # 未点赞，则添加点赞
        new_like = Like(user_id=current_user.id, post_id=post.id)
        db.session.add(new_like)
        db.session.commit()
        action = 'liked'
    
    # 返回更新后的点赞数
    likes_count = Like.query.filter_by(post_id=post.id).count()
    
    return jsonify({
        'success': True,
        'action': action,
        'likes': likes_count
    })

# 称号管理页面 - 集成所有功能
@app.route('/admin/titles', methods=['GET', 'POST'])
@login_required
def admin_titles():
    if not current_user.is_admin:
        flash('权限不足', 'danger')
        return redirect(url_for('index'))
    
    # 处理POST请求 - 所有称号操作
    if request.method == 'POST':
        action = request.form.get('action', '')
        
        # 添加称号
        if action == 'add':
            name = request.form.get('name')
            color = request.form.get('color')
            
            if name and color:
                title = Title(name=name, color=color)
                db.session.add(title)
                db.session.commit()
                flash('添加称号成功', 'success')
            else:
                flash('请填写所有必填字段', 'danger')
        
        # 编辑称号
        elif action == 'edit':
            title_id = request.form.get('title_id')
            name = request.form.get('name')
            color = request.form.get('color')
            
            if title_id and name and color:
                title = Title.query.get_or_404(int(title_id))
                title.name = name
                title.color = color
                db.session.commit()
                flash('更新称号成功', 'success')
            else:
                flash('请填写所有必填字段', 'danger')
        
        # 删除称号
        elif action == 'delete':
            title_id = request.form.get('title_id')
            
            if title_id:
                title = Title.query.get_or_404(int(title_id))
                db.session.delete(title)
                db.session.commit()
                flash('称号已删除', 'success')
            else:
                flash('无效的称号ID', 'danger')
                
        return redirect(url_for('admin_titles'))
    
    # 处理GET请求 - 显示页面
    titles = Title.query.all()
    return render_template('admin/titles.html', titles=titles)

# 用户称号管理
@app.route('/admin/user-titles', methods=['GET'])
@login_required
def admin_user_titles():
    if not current_user.is_admin:
        flash('权限不足', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    # 重要：添加所有称号列表供模板使用
    all_titles = Title.query.all()
    
    return render_template('admin/user_titles.html', users=users, all_titles=all_titles)

# 管理单个用户的称号
@app.route('/admin/user-titles/<int:user_id>', methods=['POST'])
@login_required
def admin_manage_user_titles(user_id):
    if not current_user.is_admin:
        flash('没有权限访问此页面', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # 获取表单数据
    current_titles = request.form.getlist('current_titles')
    new_titles = request.form.getlist('new_titles')
    
    # 转换为整数
    current_titles = [int(id) for id in current_titles]
    new_titles = [int(id) for id in new_titles]
    
    # 获取所有用户当前称号
    all_user_titles = [title.id for title in user.titles]
    
    # 需要移除的称号
    to_remove = [title_id for title_id in all_user_titles if title_id not in current_titles]
    
    # 需要添加的称号
    to_add = [title_id for title_id in new_titles if title_id not in all_user_titles]
    
    # 处理移除
    for title_id in to_remove:
        title = Title.query.get(title_id)
        if title in user.titles:
            user.titles.remove(title)
    
    # 处理添加
    for title_id in to_add:
        title = Title.query.get(title_id)
        if title and title not in user.titles:
            user.titles.append(title)
    
    db.session.commit()
    flash(f'用户 {user.username} 的称号已更新', 'success')
    return redirect(url_for('admin_user_titles'))

# 辅助函数，获取用户可用的称号（排除已有的）
def available_titles(user):
    user_title_ids = [title.id for title in user.titles]
    return Title.query.filter(~Title.id.in_(user_title_ids)).all()

# 添加到 Jinja 环境中
app.jinja_env.globals.update(available_titles=available_titles)

# 选择佩戴称号
@app.route('/profile/wear-title/<int:title_id>', methods=['POST'])
@login_required
@csrf.exempt  # 添加这行来豁免CSRF保护
def wear_title(title_id):
    # 检查称号是否存在且用户拥有
    title = Title.query.get_or_404(title_id)
    
    # 添加调试输出
    print(f"尝试佩戴称号: {title.name} (ID:{title_id})")
    print(f"用户拥有的称号IDs: {[t.id for t in current_user.titles]}")
    
    if title not in current_user.titles:
        flash('您没有拥有这个称号', 'danger')
        return redirect(url_for('profile'))
    
    # 更新用户佩戴的称号
    current_user.wearing_title_id = title_id
    
    # 确保更改被保存
    try:
        db.session.commit()
        print(f"成功更新佩戴称号为: {title_id}")
    except Exception as e:
        db.session.rollback()
        print(f"更新称号失败: {e}")
        flash('更新称号失败，请重试', 'danger')
    
    flash(f'成功佩戴称号: {title.name}', 'success')
    return redirect(url_for('profile'))

# 取消佩戴称号
@app.route('/profile/remove-title', methods=['POST'])
@login_required
@csrf.exempt  # 添加这行来豁免CSRF保护
def remove_wearing_title():
    current_user.wearing_title_id = None
    db.session.commit()
    
    flash('已取消佩戴称号', 'success')
    return redirect(url_for('profile'))

# 标签列表页面
@app.route('/tags')
def tags_list():
    # 获取搜索查询
    query = request.args.get('q', '')
    
    # 根据搜索查询过滤标签
    if query:
        tags = Tag.query.filter(Tag.name.ilike(f'%{query}%')).all()
    else:
        tags = Tag.query.all()
    
    # 获取每个标签的文章数量
    for tag in tags:
        tag.post_count = db.session.query(post_tags).filter_by(tag_id=tag.id).count()
    
    return render_template('tags_list.html', tags=tags, query=query)

# 分类列表页面
@app.route('/categories')
def categories():
    all_categories = Category.query.all()
    
    # 获取每个分类的文章数量
    for category in all_categories:
        category.post_count = Post.query.filter_by(category_id=category.id).count()
    
    return render_template('categories.html', categories=all_categories)

# 日志模型
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # 日志类型：user, article, database, system
    action = db.Column(db.String(50), nullable=False)  # 操作类型：login, view, update, create, delete等
    message = db.Column(db.Text, nullable=False)  # 日志详细信息
    ip_address = db.Column(db.String(50), nullable=True)  # 用户IP地址
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # 相关用户ID（可为空）
    user = db.relationship('User', backref=db.backref('logs', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Log {self.type}:{self.action}>'

# 全局变量，用于防止递归调用
_logging_in_progress = False

# 日志记录函数
def log_activity(type, action, message, user_id=None):
    # 防止递归调用
    global _logging_in_progress
    if _logging_in_progress:
        return
    
    try:
        _logging_in_progress = True
        
        # 获取用户真实IP地址
        ip_address = None
        user_agent = None
        if request:
            ip_address = get_real_ip()  # 使用新的IP获取函数
            user_agent = request.headers.get('User-Agent', '')
        
        # 创建日志记录
        log_entry = Log(
            type=type,
            action=action,
            message=message,
            ip_address=ip_address,
            user_id=user_id
        )
        
        # 如果没有用户ID但有IP地址，在消息中添加IP信息
        if not user_id and ip_address:
            # 如果消息中没有包含IP信息，添加它
            if f"IP: {ip_address}" not in message:
                log_entry.message = f"[IP: {ip_address}] {message}"
        
        # 使用独立的会话添加日志
        from sqlalchemy.orm import Session
        
        engine = db.engine
        session = Session(engine)
        
        try:
            session.add(log_entry)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"日志记录失败: {e}")
        finally:
            session.close()
            
    finally:
        _logging_in_progress = False

# 添加管理员后台日志功能
@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # 获取筛选条件
    type_filter = request.args.get('type', '')
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    ip_filter = request.args.get('ip', '')
    message_filter = request.args.get('message', '')  # 新增消息内容筛选
    
    # 获取所有唯一的IP地址列表
    unique_ips = db.session.query(Log.ip_address).distinct().filter(Log.ip_address != None).order_by(Log.ip_address).all()
    unique_ips = [ip[0] for ip in unique_ips if ip[0]]  # 把元组转为列表并过滤None值
    
    # 构建查询
    query = Log.query
    
    if type_filter:
        query = query.filter(Log.type == type_filter)
    if action_filter:
        query = query.filter(Log.action == action_filter)
    if user_filter:
        query = query.join(User, Log.user_id == User.id).filter(User.username.contains(user_filter))
    if ip_filter:
        query = query.filter(Log.ip_address.contains(ip_filter))
    if message_filter:  # 添加消息内容筛选
        query = query.filter(Log.message.contains(message_filter))
    
    # 分页
    pagination = query.order_by(Log.created_at.desc()).paginate(page=page, per_page=per_page)
    logs = pagination.items
    
    # 获取所有唯一操作类型供筛选器使用
    unique_actions = db.session.query(Log.action).distinct().all()
    unique_actions = [action[0] for action in unique_actions]
    
    # 统计各类型日志数量
    stats = {
        'total': Log.query.count(),
        'user': Log.query.filter_by(type='user').count(),
        'article': Log.query.filter_by(type='article').count(),
        'system': Log.query.filter_by(type='system').count(),
        'http': Log.query.filter_by(type='http').count(),
    }
    
    return render_template('admin/logs.html', 
                           logs=logs, 
                           pagination=pagination,
                           stats=stats,
                           unique_actions=unique_actions,
                           unique_ips=unique_ips,
                           type_filter=type_filter,
                           action_filter=action_filter,
                           user_filter=user_filter,
                           ip_filter=ip_filter,
                           message_filter=message_filter)  # 传递消息筛选参数

@app.before_request
def log_request():
    # 跳过静态文件和资源请求的日志记录
    if request.path.startswith('/static/') or request.path.endswith(('.js', '.css', '.png', '.jpg', '.ico')):
        return
    
    # 只记录特定重要操作，减少日志数量
    if not any(kw in request.path for kw in ['/admin/', '/post/', '/login', '/register', '/logout']):
        return
    
    # 记录请求信息
    user_id = current_user.id if current_user.is_authenticated else None
    path = request.path
    method = request.method
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    log_message = f"{method} {path} - IP: {ip}"
    
    # 只记录特定类型的请求，减少日志数量
    if 'post/' in path and method == 'GET':
        # 只记录文章浏览
        log_activity('article', 'view', log_message, user_id)
    elif 'admin/' in path and not path.startswith('/admin/logs'):
        # 只记录管理后台重要操作
        log_activity('system', 'admin_access', log_message, user_id)
    elif method == 'POST' and not path.startswith('/admin/logs'):
        # 只记录关键表单提交
        if any(key in path for key in ['/login', '/register', '/create', '/edit', '/delete']):
            log_activity('system', 'form_submit', log_message, user_id)

# 修改数据库事件监听器
@event.listens_for(db.session, 'after_commit')
def log_db_changes(session):
    # 防止递归记录
    global _logging_in_progress
    if _logging_in_progress:
        return
        
    # 检查当前会话中是否有已标记待记录的更改
    if hasattr(session, '_log_changes') and session._log_changes:
        changes = session._log_changes.copy()  # 创建副本
        session._log_changes = []  # 清除原始列表
        
        # 获取当前用户信息
        user_id = None
        from flask import has_request_context, session as flask_session
        if has_request_context() and 'user_id' in flask_session:
            user_id = flask_session['user_id']
        
        # 记录数据库更改
        for entity, operation in changes:
            # 跳过对Log模型的操作，避免循环记录
            if entity.__class__.__name__ == 'Log':
                continue
                
            entity_type = entity.__class__.__name__
            entity_id = getattr(entity, 'id', None)
            
            message = f"{operation} {entity_type} (ID: {entity_id})"
            log_activity('database', operation.lower(), message, user_id)

@event.listens_for(db.session, 'before_commit')
def track_db_changes(session):
    # 初始化待记录的更改列表
    if not hasattr(session, '_log_changes'):
        session._log_changes = []
    
    # 记录所有新增和修改的对象
    for obj in session.new:
        session._log_changes.append((obj, 'INSERT'))
    
    for obj in session.dirty:
        session._log_changes.append((obj, 'UPDATE'))
    
    # 记录所有删除的对象
    for obj in session.deleted:
        session._log_changes.append((obj, 'DELETE'))

# 用户权限管理页面
@app.route('/admin/permissions')
@login_required
def admin_permissions():
    if not current_user.is_admin:
        flash('只有管理员可以访问此页面', 'danger')
        return redirect(url_for('index'))
    
    # 获取所有用户，按ID排序
    users = User.query.order_by(User.id).all()
    
    # 获取权限变更日志
    logs = Log.query.filter_by(action='update_permission').order_by(Log.created_at.desc()).limit(20).all()
    
    # 记录权限管理页面访问
    log_activity('system', 'access_permissions', f'管理员 {current_user.username} 访问了权限管理页面', current_user.id)
    
    return render_template('admin/permissions.html', users=users, logs=logs)

# 更新用户权限
@app.route('/admin/permissions/update/<int:user_id>', methods=['POST'])
@login_required
def update_permissions(user_id):
    if not current_user.is_admin:
        flash('只有管理员可以修改权限', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # 超级管理员（ID=1）不允许被降级
    if user.id == 1:
        flash('不能修改超级管理员的权限', 'warning')
        return redirect(url_for('admin_permissions'))
    
    # 当前管理员不能修改自己的权限
    if user.id == current_user.id:
        flash('不能修改自己的权限', 'warning')
        return redirect(url_for('admin_permissions'))
    
    # 更新权限
    is_admin = True if request.form.get('is_admin') == 'on' else False
    
    # 记录原始状态
    old_status = "管理员" if user.is_admin else "普通用户"
    new_status = "管理员" if is_admin else "普通用户"
    
    user.is_admin = is_admin
    db.session.commit()
    
    # 记录权限变更
    log_activity('user', 'update_permission', 
                f'管理员 {current_user.username} 将用户 {user.username} 的权限从 {old_status} 修改为 {new_status}', 
                current_user.id)
    
    flash(f'已成功更新 {user.username} 的权限', 'success')
    return redirect(url_for('admin_permissions'))

# 服务器状态页面
@app.route('/server-status')
@login_required  # 确保用户必须登录
def server_status():
    # 如果需要限制只有管理员可访问，可以添加以下代码
    if not current_user.is_admin:
        flash('只有管理员可以访问服务器状态页面', 'danger')
        return redirect(url_for('index'))
    
    # 使用东八区时间
    current_time = datetime.now().strftime("%H:%M:%S")
    
    # 获取系统信息
    system_info = {
        'system': platform.system(),
        'platform': platform.platform(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'hostname': socket.gethostname(),
    }
    
    # CPU信息
    cpu_info = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'cpu_count': psutil.cpu_count(logical=True),
        'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A',
    }
    
    # 内存信息
    memory = psutil.virtual_memory()
    memory_info = {
        'total': round(memory.total / (1024 ** 3), 2),  # GB
        'available': round(memory.available / (1024 ** 3), 2),  # GB
        'used': round(memory.used / (1024 ** 3), 2),  # GB
        'percent': memory.percent,
    }
    
    # 磁盘信息
    disk = psutil.disk_usage('/')
    disk_info = {
        'total': round(disk.total / (1024 ** 3), 2),  # GB
        'used': round(disk.used / (1024 ** 3), 2),  # GB
        'free': round(disk.free / (1024 ** 3), 2),  # GB
        'percent': disk.percent,
    }
    
    # 启动时间处理
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    # 不要将boot_time转换为字符串
    # boot_time = boot_time.strftime("%H:%M:%S")  <-- 这行导致了错误
    uptime = datetime.now() - boot_time  # 现在应该可以正常计算
    uptime_str = str(timedelta(seconds=uptime.total_seconds()))
    
    # 网络状态
    # 检测网络延迟
    try:
        ping_result = subprocess.run(['ping', '-c', '1', '8.8.8.8'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  text=True, 
                                  timeout=5)
        ping_output = ping_result.stdout
        # 提取延迟时间
        if 'time=' in ping_output:
            ping_time = ping_output.split('time=')[1].split(' ')[0]
        else:
            ping_time = 'N/A'
    except:
        ping_time = 'N/A'
    
    # 进程信息
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
        try:
            pinfo = proc.info
            pinfo['memory_percent'] = round(pinfo['memory_percent'], 2)
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    # 按内存使用率排序，取前10个
    processes = sorted(processes, key=lambda p: p['memory_percent'], reverse=True)[:10]
    
    # 获取Flask应用信息
    app_info = {
        'version': '1.0.0',
        'debug_mode': app.debug,
        'database': app.config['SQLALCHEMY_DATABASE_URI'].split('///')[0],
        'post_count': Post.query.count(),
        'user_count': User.query.count(),
        'comment_count': Comment.query.count()
    }
    
    # 服务状态
    services = [
        {'name': 'Web服务器', 'status': 'running', 'uptime': uptime_str},
        {'name': '数据库', 'status': 'running', 'uptime': uptime_str},
        {'name': '文件上传', 'status': 'running', 'uptime': uptime_str},
    ]
    
    # 记录访问日志
    log_activity('system', 'view_server_status', 
                f'用户 {current_user.username} 查看了服务器状态', 
                current_user.id)
    
    return render_template('server_status.html', 
                          system_info=system_info,
                          cpu_info=cpu_info,
                          memory_info=memory_info,
                          disk_info=disk_info,
                          uptime=uptime_str,
                          ping_time=ping_time,
                          processes=processes,
                          app_info=app_info,
                          services=services,
                          current_time=current_time)  # 添加当前时间变量

# 获取实时CPU和内存数据的API端点
@app.route('/api/system-stats')
@login_required
def system_stats():
    cpu_percent = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory()
    
    data = {
        'cpu': cpu_percent,
        'memory': memory.percent,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }
    
    return jsonify(data)

# 添加到app.py文件中的初始化部分
@app.context_processor
def inject_datetime():
    return {
        'datetime': datetime
    }

# 添加获取真实IP地址的辅助函数
def get_real_ip():
    """获取用户真实IP地址，优先检查代理报头"""
    # 检查可能包含真实IP的请求头
    headers_to_check = [
        'X-Forwarded-For',  # 常见的代理记录头
        'X-Real-IP',        # Nginx等使用
        'CF-Connecting-IP', # Cloudflare
        'True-Client-IP',   # Akamai和Cloudflare
        'X-Client-IP'       # Amazon ELB
    ]
    
    for header in headers_to_check:
        ip = request.headers.get(header)
        if ip:
            # X-Forwarded-For可能包含多个IP，取第一个（最接近客户端的）
            if header == 'X-Forwarded-For' and ',' in ip:
                ip = ip.split(',')[0].strip()
            return ip
    
    # 如果没有找到代理头，则使用直接连接的IP
    return request.remote_addr

# 安装依赖: pip install geoip2
# 需要下载MaxMind的GeoLite2数据库文件
import geoip2.database

# IP地理位置查询函数
def get_location_from_ip(ip_address):
    if not HAS_GEOIP:
        return {'country': '未知', 'city': '未知'}
    
    try:
        # 原有的geoip2代码
        with geoip2.database.Reader('path/to/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            return {
                'country': response.country.name or '未知',
                'city': response.city.name or '未知'
            }
    except Exception as e:
        app.logger.error(f"获取IP地理位置失败: {str(e)}")
        return {'country': '未知', 'city': '未知'}

# 添加Flask请求日志记录中间件
@app.before_request
def log_request_info():
    # 跳过静态文件请求的日志记录
    if request.path.startswith('/static/'):
        return
    
    # 跳过API端点，避免日志过多
    if request.path.startswith('/api/'):
        return
        
    # 获取请求信息
    method = request.method
    path = request.path
    ip = get_real_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    # 获取当前用户ID（如果已登录）
    user_id = current_user.id if current_user.is_authenticated else None
    
    # 构建与Flask原生日志相似的消息格式
    timestamp = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    log_message = f'"{method} {path}" - 用户代理: {user_agent[:50]}{"..." if len(user_agent) > 50 else ""}'
    
    # 记录请求日志
    log_activity('http', 'request', log_message, user_id)
    
# 添加响应日志记录
@app.after_request
def log_response_info(response):
    # 跳过静态文件
    if request.path.startswith('/static/'):
        return response
    
    # 跳过API端点
    if request.path.startswith('/api/'):
        return response
    
    # 获取响应状态
    status_code = response.status_code
    
    # 获取请求信息
    method = request.method
    path = request.path
    ip = get_real_ip()
    
    # 获取当前用户ID（如果已登录）
    user_id = current_user.id if current_user.is_authenticated else None
    
    # 构建日志消息（类似Flask原生日志）
    log_message = f'"{method} {path}" {status_code}'
    
    # 只记录错误响应的日志，避免数据库过大
    if status_code >= 400:
        log_activity('http', 'error', log_message, user_id)
    
    return response

# 系统消息模型
class SystemMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')  # info, success, warning, danger
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', backref='created_messages')
    
    # 发送设置
    send_to_all = db.Column(db.Boolean, default=True)  # 是否发送给所有用户
    scheduled_time = db.Column(db.DateTime, nullable=True)  # 定时发送时间
    expiry_time = db.Column(db.DateTime, nullable=True)  # 消息过期时间
    
    # 消息触发类型
    trigger_on_registration = db.Column(db.Boolean, default=False)  # 新用户注册时显示
    trigger_on_login = db.Column(db.Boolean, default=False)  # 用户登录时显示
    
    # 消息样式设置
    icon = db.Column(db.String(50), default='fas fa-bell')  # Font Awesome图标
    display_duration = db.Column(db.Integer, default=5000)  # 显示时长(毫秒)
    
    # 显示次数设置
    max_display_count = db.Column(db.Integer, default=1)  # 向每个用户显示的最大次数
    
    # 添加访客可见设置
    guest_visible = db.Column(db.Boolean, default=False)  # 是否向未登录用户显示
    
    # 关联已读记录
    read_records = db.relationship('MessageReadRecord', backref='message', lazy='dynamic')
    
    def __repr__(self):
        return f'<SystemMessage {self.title}>'
    
    @property
    def is_scheduled(self):
        """判断是否为定时消息"""
        return self.scheduled_time is not None and self.scheduled_time > datetime.utcnow()
    
    @property
    def is_expired(self):
        """判断消息是否已过期"""
        return self.expiry_time is not None and self.expiry_time < datetime.utcnow()
    
    @property
    def is_active(self):
        """判断消息是否处于活跃状态"""
        now = datetime.utcnow()
        if self.expiry_time and now > self.expiry_time:
            return False
        if self.scheduled_time and now < self.scheduled_time:
            return False
        return True

# 消息阅读记录模型
class MessageReadRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('system_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    read_at = db.Column(db.DateTime, default=datetime.utcnow)
    display_count = db.Column(db.Integer, default=1)  # 已显示给用户的次数
    
    # 组合唯一约束，确保每个用户对每条消息只有一条阅读记录
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', name='_message_user_uc'),)
    
    def __repr__(self):
        return f'<MessageReadRecord {self.message_id} - {self.user_id}>'

# 系统消息管理页面
@app.route('/admin/messages', methods=['GET'])
@login_required
def admin_messages():
    if not current_user.is_admin:
        flash('只有管理员可以访问此页面', 'danger')
        return redirect(url_for('index'))
    
    # 获取所有消息，按创建时间降序排列
    messages = SystemMessage.query.order_by(SystemMessage.created_at.desc()).all()
    
    # 统计各类消息
    stats = {
        'total': SystemMessage.query.count(),
        'active': SystemMessage.query.filter(
            (SystemMessage.expiry_time == None) | 
            (SystemMessage.expiry_time > datetime.utcnow())
        ).count(),
        'scheduled': SystemMessage.query.filter(
            SystemMessage.scheduled_time > datetime.utcnow()
        ).count(),
        'expired': SystemMessage.query.filter(
            SystemMessage.expiry_time < datetime.utcnow()
        ).count()
    }
    
    # 记录管理操作
    log_activity('system', 'view_messages', f'管理员查看了系统消息列表', current_user.id)
    
    return render_template('admin/messages.html', messages=messages, stats=stats)

# 创建/编辑系统消息
@app.route('/admin/messages/edit/<int:id>', methods=['GET', 'POST'])
@app.route('/admin/messages/create', methods=['GET', 'POST'])
@login_required
def edit_message(id=None):
    if not current_user.is_admin:
        flash('只有管理员可以管理系统消息', 'danger')
        return redirect(url_for('index'))
    
    # 初始化消息对象
    message = None
    if id:
        message = SystemMessage.query.get_or_404(id)
        form_title = '编辑系统消息'
    else:
        form_title = '创建新系统消息'
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        message_type = request.form.get('type', 'info')
        icon = request.form.get('icon', 'fas fa-bell')
        send_to_all = request.form.get('send_to_all') == 'on'
        display_duration = int(request.form.get('display_duration', 5000))
        
        # 处理定时发送
        scheduled_date = request.form.get('scheduled_date')
        scheduled_time = request.form.get('scheduled_time')
        scheduled_datetime = None
        if scheduled_date and scheduled_time:
            try:
                scheduled_datetime = datetime.strptime(f'{scheduled_date} {scheduled_time}', '%Y-%m-%d %H:%M')
            except ValueError:
                flash('定时发送日期格式无效', 'danger')
        
        # 处理过期时间
        expiry_date = request.form.get('expiry_date')
        expiry_time = request.form.get('expiry_time')
        expiry_datetime = None
        if expiry_date and expiry_time:
            try:
                expiry_datetime = datetime.strptime(f'{expiry_date} {expiry_time}', '%Y-%m-%d %H:%M')
            except ValueError:
                flash('过期时间格式无效', 'danger')
        
        # 处理触发事件
        trigger_on_registration = request.form.get('trigger_on_registration') == 'on'
        trigger_on_login = request.form.get('trigger_on_login') == 'on'
        
        # 处理显示次数
        max_display_count = int(request.form.get('max_display_count', 1))
        if max_display_count < 1:
            max_display_count = 1
        
        # 处理访客可见
        guest_visible = request.form.get('guest_visible') == 'on'
        
        if not title or not content:
            flash('标题和内容不能为空', 'danger')
        else:
            # 创建新消息或更新现有消息
            if message is None:
                message = SystemMessage(creator_id=current_user.id)
            
            # 更新消息属性
            message.title = title
            message.content = content
            message.type = message_type
            message.icon = icon
            message.send_to_all = send_to_all
            message.scheduled_time = scheduled_datetime
            message.expiry_time = expiry_datetime
            message.trigger_on_registration = trigger_on_registration
            message.trigger_on_login = trigger_on_login
            message.display_duration = display_duration
            message.max_display_count = max_display_count
            message.guest_visible = guest_visible  # 添加新字段
            
            try:
                if id is None:
                    db.session.add(message)
                    log_action = 'create'
                    flash_message = '消息创建成功'
                else:
                    log_action = 'update'
                    flash_message = '消息更新成功'
                
                db.session.commit()
                flash(flash_message, 'success')
                
                # 记录管理操作
                log_activity('system', f'{log_action}_message', 
                            f'管理员{log_action=="create"and "创建" or "更新"}了系统消息: {message.title}', 
                            current_user.id)
                
                return redirect(url_for('admin_messages'))
            except Exception as e:
                db.session.rollback()
                flash(f'操作失败: {str(e)}', 'danger')
    
    # GET请求，显示表单
    return render_template('admin/edit_message.html', 
                          message=message, 
                          form_title=form_title)

# 删除系统消息
@app.route('/admin/messages/delete/<int:id>', methods=['POST'])
@login_required
def delete_message(id):
    if not current_user.is_admin:
        flash('只有管理员可以删除系统消息', 'danger')
        return redirect(url_for('index'))
    
    message = SystemMessage.query.get_or_404(id)
    
    try:
        # 先删除所有关联的已读记录
        MessageReadRecord.query.filter_by(message_id=id).delete()
        
        # 再删除消息本身
        title = message.title  # 保存标题用于日志
        db.session.delete(message)
        db.session.commit()
        
        flash('消息已成功删除', 'success')
        
        # 记录管理操作
        log_activity('system', 'delete_message', f'管理员删除了系统消息: {title}', current_user.id)
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'danger')
    
    return redirect(url_for('admin_messages'))

# 获取未读消息API
@app.route('/api/unread-messages', methods=['GET'])
def get_unread_messages():
    # 当前时间
    now = datetime.utcnow()
    
    # 对于未登录用户，只显示设置为"访客可见"的消息
    if not current_user.is_authenticated:
        # 获取从请求中传来的已读消息ID列表
        read_message_ids = request.args.get('read_ids', '')
        read_ids = read_message_ids.split(',') if read_message_ids else []
        
        # 查询适合访客的常规消息
        guest_messages = SystemMessage.query.filter(
            # 消息在有效期内
            ((SystemMessage.expiry_time == None) | (SystemMessage.expiry_time > now)),
            # 消息已经到了计划发送时间
            ((SystemMessage.scheduled_time == None) | (SystemMessage.scheduled_time <= now)),
            # 消息设置为访客可见
            SystemMessage.guest_visible == True,
            # 过滤掉用户已在本地标记为已读的消息
            ~SystemMessage.id.in_([int(id) for id in read_ids if id.isdigit()])
        ).all()
        
        # 格式化消息数据
        messages_data = []
        for msg in guest_messages:
            messages_data.append({
                'id': msg.id,
                'title': msg.title,
                'content': msg.content,
                'type': msg.type,
                'icon': msg.icon,
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'display_duration': msg.display_duration,
                'message_type': 'guest',
                'for_guest': True  # 标记这是给访客的消息
            })
        
        return jsonify(messages_data)
    
    # 已登录用户的现有逻辑保持不变
    # 获取已读消息记录
    read_records = {r.message_id: r for r in 
                   MessageReadRecord.query.filter_by(user_id=current_user.id).all()}
    
    # 分别查询三种类型的消息
    messages_to_show = []
    
    # 1. 常规消息 - 只获取未读的
    regular_messages = SystemMessage.query.filter(
        # 消息在有效期内
        ((SystemMessage.expiry_time == None) | (SystemMessage.expiry_time > now)),
        # 消息已经到了计划发送时间
        ((SystemMessage.scheduled_time == None) | (SystemMessage.scheduled_time <= now)),
        # 是常规消息(发送给所有人且非触发类型)
        SystemMessage.send_to_all,
        ~SystemMessage.trigger_on_login,
        ~SystemMessage.trigger_on_registration,
        # 用户未读过的消息
        ~SystemMessage.id.in_([mid for mid in read_records.keys()])
    ).all()
    messages_to_show.extend(regular_messages)
    
    # 2. 登录触发消息 - 检查是否有最新登录事件
    login_time = session.get('login_event_time', 0)
    if login_time > 0:
        login_messages = SystemMessage.query.filter(
            # 消息在有效期内
            ((SystemMessage.expiry_time == None) | (SystemMessage.expiry_time > now)),
            # 消息已经到了计划发送时间
            ((SystemMessage.scheduled_time == None) | (SystemMessage.scheduled_time <= now)),
            # 是登录触发消息
            SystemMessage.trigger_on_login
        ).all()
        
        # 过滤出未在本次登录会话中显示过的消息
        for msg in login_messages:
            record = read_records.get(msg.id)
            # 如果没有记录，或者记录的时间早于本次登录时间
            if not record or record.read_at.timestamp() < login_time:
                messages_to_show.append(msg)
    
    # 3. 注册触发消息 - 检查是否有注册事件
    registration_time = session.get('registration_event_time', 0)
    if registration_time > 0:
        # 只在注册后首次获取消息时显示注册消息，之后清除注册时间标记
        registration_messages = SystemMessage.query.filter(
            # 消息在有效期内
            ((SystemMessage.expiry_time == None) | (SystemMessage.expiry_time > now)),
            # 消息已经到了计划发送时间
            ((SystemMessage.scheduled_time == None) | (SystemMessage.scheduled_time <= now)),
            # 是注册触发消息
            SystemMessage.trigger_on_registration
        ).all()
        
        # 添加到显示队列
        messages_to_show.extend(registration_messages)
        
        # 清除注册标记，确保只显示一次
        session.pop('registration_event_time', None)
    
    # 格式化消息数据
    messages_data = []
    for msg in messages_to_show:
        messages_data.append({
            'id': msg.id,
            'title': msg.title,
            'content': msg.content,
            'type': msg.type,
            'icon': msg.icon,
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'display_duration': msg.display_duration,
            'message_type': 'regular' if not (msg.trigger_on_login or msg.trigger_on_registration) else 
                           ('login' if msg.trigger_on_login else 'registration'),
            'for_guest': False  # 标记这不是给访客的消息
        })
    
    return jsonify(messages_data)

# 完全重写消息标记已读API，使用最简单的方式
@app.route('/api/mark-message-read/<int:message_id>', methods=['GET'])
def mark_message_read(message_id):
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'error': '用户未登录'}), 401
    
    # 记录调试信息
    app.logger.info(f"尝试标记消息 {message_id} 为已读")
    
    # 检查消息是否存在
    message = SystemMessage.query.get(message_id)
    if not message:
        return jsonify({'success': False, 'error': f'消息不存在(ID: {message_id})'}), 404
    
    try:
        # 检查是否已有记录
        record = MessageReadRecord.query.filter_by(
            message_id=message_id, 
            user_id=current_user.id
        ).first()
        
        if not record:
            # 创建新的阅读记录
            record = MessageReadRecord(
                message_id=message_id,
                user_id=current_user.id,
                display_count=1
            )
            db.session.add(record)
        else:
            # 更新已有记录
            record.display_count += 1
            record.read_at = datetime.now(UTC)
            
        db.session.commit()
        return jsonify({'success': True, 'message': f'成功标记消息 {message_id} 为已读'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"标记消息已读失败: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# 添加一个紧急修复路由来修复数据库结构
@app.route('/fix_database')
@login_required
def fix_database():
    if not current_user.is_admin:
        flash('只有管理员可以执行此操作', 'danger')
        return redirect(url_for('index'))
    
    try:
        # 添加访客可见列
        db.session.execute('ALTER TABLE system_message ADD COLUMN guest_visible BOOLEAN DEFAULT 0')
        db.session.commit()
        flash('成功添加 guest_visible 列！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'添加列失败: {str(e)}', 'warning')
        
    # 检查所有需要的列是否存在
    try:
        # 尝试查询来验证列是否存在
        test_query = db.session.execute('SELECT guest_visible FROM system_message LIMIT 1')
        test_query.close()
        flash('数据库结构验证成功，所有必要的列都存在', 'success')
    except Exception as e:
        flash(f'数据库结构验证失败: {str(e)}', 'danger')
    
    return redirect(url_for('admin'))

# 在当前app.py中添加这个辅助函数，用于生成正确的CSRF令牌
def generate_csrf_token():
    """生成CSRF令牌并确保session中有值"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = generate_csrf()
    return session['_csrf_token']

# 确保所有模板可以访问CSRF令牌
@app.context_processor
def inject_csrf_token():
    """向所有模板注入CSRF令牌函数"""
    def _csrf_token():
        return generate_csrf_token()
    return dict(csrf_token=_csrf_token)

# 确保管理员权限切换路由有正确的CSRF保护
@app.route('/admin/users/toggle_admin', methods=['POST'])
@login_required
def toggle_admin():
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': '没有权限执行此操作'}), 403
    
    # 获取请求数据
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': '没有提供数据'}), 400
        
    user_id = data.get('user_id')
    is_admin = data.get('is_admin')
    
    if not user_id:
        return jsonify({'success': False, 'error': '未提供用户ID'}), 400
        
    # 查找用户
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': '用户不存在'}), 404
        
    # 不能修改自己的管理员状态
    if user.id == current_user.id:
        return jsonify({'success': False, 'error': '不能修改自己的管理员状态'}), 400
    
    # 更新用户管理员状态
    try:
        user.is_admin = bool(is_admin)
        db.session.commit()
        
        # 记录活动
        action = '授予' if user.is_admin else '撤销'
        log_activity('admin', 'toggle_admin', f'{action} {user.username} 的管理员权限', current_user.id)
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# 临时禁用特定路由的CSRF保护（仅用于调试，不要在生产环境中使用）
@app.route('/admin/users/toggle_admin_no_csrf', methods=['POST'])
@csrf.exempt  # 豁免CSRF保护
@login_required
def toggle_admin_no_csrf():
    # 与toggle_admin相同的代码...
    pass

# 为update_permissions路由添加CSRF豁免
@app.route('/admin/users/update_permissions/<int:user_id>', methods=['POST'])
@csrf.exempt  # 豁免CSRF保护
@login_required
def update_permissions_no_csrf(user_id):
    if not current_user.is_admin:
        flash('您没有执行此操作的权限', 'danger')
        return redirect(url_for('admin'))
        
    # 获取表单数据
    is_admin = request.form.get('is_admin') == 'on'
    
    # 查找用户
    user = User.query.get_or_404(user_id)
    
    # 不能修改超级管理员或自己的状态
    if user.id == 1 or user.id == current_user.id:
        flash('无法修改该用户的权限', 'warning')
        return redirect(url_for('admin_permissions'))
    
    # 记录旧状态
    old_status = '管理员' if user.is_admin else '普通用户'
    
    # 更新权限
    user.is_admin = is_admin
    
    # 记录新状态
    new_status = '管理员' if user.is_admin else '普通用户'
    
    try:
        db.session.commit()
        # 记录操作日志
        log_activity('admin', 'update_permission', 
                    f'将用户 {user.username} 的权限从 {old_status} 更改为 {new_status}', 
                    current_user.id)
        flash(f'已将用户 {user.username} 的权限更新为 {new_status}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'更新权限失败: {str(e)}', 'danger')
    
    return redirect(url_for('admin_permissions'))

# 添加CSRF错误处理器，使错误消息更友好
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.warning(f'CSRF错误: {str(e)}')
    return render_template('errors/csrf_error.html', reason=e.description), 400

# 在app.py中添加以下代码来处理geoip2模块缺失的情况
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False
    app.logger.warning('geoip2模块未安装，地理位置功能将不可用')

# 添加一个初始化数据库的路由
@app.route('/init_db')
def init_db():
    try:
        with app.app_context():
            db.create_all()
            
            # 创建管理员账户（如果不存在）
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    password=generate_password_hash('admin123'),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
                
            return '数据库初始化成功！请<a href="/login">登录</a>'
    except Exception as e:
        return f'数据库初始化失败: {str(e)}'

# 如果有专门处理编辑器上传的函数
@app.route('/upload_editor_image', methods=['POST'])
def upload_editor_image():
    # ... 现有代码 ...
    
    # 在保存文件之前，确保目录存在
    import os
    
    # 构建完整的目标路径
    upload_folder = os.path.join(app.static_folder, 'uploads')
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder, exist_ok=True)
    
    # ... 继续处理保存文件 ...

# 在app.py的初始化部分添加
import os

# 创建必要的目录
def ensure_directories_exist():
    # 确保上传目录存在
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    upload_dir = os.path.join(static_dir, 'uploads')
    editor_dir = os.path.join(upload_dir, 'editor')
    background_dir = os.path.join(upload_dir, 'background')
    
    for directory in [static_dir, upload_dir, editor_dir, background_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            app.logger.info(f"创建目录: {directory}")

# 在应用启动时调用
ensure_directories_exist()

# 查找像这样的文件上传处理函数
@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': '没有文件部分'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'})
    
    if file and allowed_file(file.filename):
        # 使用绝对路径
        import os
        
        # 确保上传目录存在 - 使用绝对路径
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        upload_folder = os.path.join(BASE_DIR, 'static', 'uploads')
        
        # 确保目录存在
        os.makedirs(upload_folder, exist_ok=True)
        
        # 如果是编辑器上传，可能有子目录
        if 'editor' in request.form:
            editor_folder = os.path.join(upload_folder, 'editor')
            os.makedirs(editor_folder, exist_ok=True)
            upload_folder = editor_folder
        
        # 保存文件
        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_folder, filename)
        
        # 调试信息
        app.logger.info(f"尝试保存文件到: {file_path}")
        
        try:
            file.save(file_path)
            return jsonify({'location': f'/static/uploads/{filename}'})
        except Exception as e:
            app.logger.error(f"文件保存失败: {str(e)}")
            return jsonify({'error': f'文件保存失败: {str(e)}'})

def url_is_safe(url):
    """检查重定向URL是否安全"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, url))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# 会话配置，确保稳定的会话处理
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 会话有效期
app.config['SESSION_USE_SIGNER'] = True  # 签名会话cookie

# 尝试设置Session
try:
    from flask_session import Session
    Session(app)
except ImportError:
    print("Flask-Session未安装，使用默认会话管理")

# 更新用户称号
@app.route('/admin/user-titles/<int:user_id>/update', methods=['POST'])
@login_required
def admin_update_user_titles(user_id):
    if not current_user.is_admin:
        flash('权限不足', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # 获取表单中的数据
    selected_title_ids = request.form.getlist(f'user_titles')
    wearing_title_id = request.form.get(f'wearing_title_{user_id}')
    
    # 清除现有称号关联
    user.titles = []
    
    # 添加选择的称号
    for title_id in selected_title_ids:
        title = Title.query.get(int(title_id))
        if title:
            user.titles.append(title)
    
    # 设置正在佩戴的称号
    if wearing_title_id:
        wearing_title_id = int(wearing_title_id)
        if any(t.id == wearing_title_id for t in user.titles):
            user.wearing_title_id = wearing_title_id
        else:
            user.wearing_title_id = None
    else:
        user.wearing_title_id = None
    
    db.session.commit()
    flash(f'已更新用户 {user.username} 的称号', 'success')
    return redirect(url_for('admin_user_titles'))

# 添加自定义模板函数
@app.context_processor
def utility_processor():
    def available_titles(user):
        """获取用户可用的称号（尚未拥有的称号）"""
        return Title.query.filter(~Title.users.contains(user)).all()
    
    return {
        'available_titles': available_titles
    }

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # 如果用户不是管理员,返回403禁止访问
        return func(*args, **kwargs)
    return decorated_view

@app.route('/admin/api/logs/<int:log_id>')
@login_required
@admin_required
def get_log_detail(log_id):
    log = Log.query.get_or_404(log_id)
    
    # 确保返回完整的消息内容
    return jsonify({
        'id': log.id,
        'type': log.type,
        'action': log.action,
        'user': {
            'id': log.user.id,
            'username': log.user.username
        } if log.user else None,
        'ip': log.ip_address,
        'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'message': log.message  # 确保这里返回完整消息
    })

@app.route('/admin/users/<int:user_id>/titles', methods=['POST'], endpoint='update_user_titles')
@login_required
@admin_required
def admin_update_user_titles(user_id):
    user = User.query.get_or_404(user_id)
    
    selected_titles = request.form.getlist('user_titles')
    wearing_title_id = request.form.get(f'wearing_title_{user_id}')
    
    # 更新用户的称号
    user.titles = Title.query.filter(Title.id.in_(selected_titles)).all()
    
    if wearing_title_id:
        user.wearing_title_id = int(wearing_title_id)
    else:
        user.wearing_title_id = None
        
    db.session.commit()
    
    flash('用户称号已更新', 'success')
    return redirect(url_for('admin_user_titles'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    with app.app_context():
        db.create_all()
        create_initial_data()
        
        # 尝试创建 wearing_title_id 列
        try:
            db.session.execute('ALTER TABLE user ADD COLUMN wearing_title_id INTEGER REFERENCES title(id)')
            db.session.commit()
            print("成功添加 wearing_title_id 列")
        except Exception as e:
            db.session.rollback()
            print(f"列可能已存在: {e}")
        
        # 尝试创建 tag.color 列
        try:
            db.session.execute('ALTER TABLE tag ADD COLUMN color VARCHAR(20) DEFAULT "#6c757d"')
            db.session.commit()
            print("成功添加 tag.color 列")
        except Exception as e:
            db.session.rollback()
            print(f"列可能已存在: {e}")
        
        # 添加系统消息显示次数列
        try:
            db.session.execute('ALTER TABLE system_message ADD COLUMN max_display_count INTEGER DEFAULT 1')
            db.session.commit()
            print("成功添加 system_message.max_display_count 列")
        except Exception as e:
            db.session.rollback()
            print(f"列可能已存在: {e}")
            
        # 添加消息阅读记录显示计数列
        try:
            db.session.execute('ALTER TABLE message_read_record ADD COLUMN display_count INTEGER DEFAULT 1')
            db.session.commit()
            print("成功添加 message_read_record.display_count 列")
        except Exception as e:
            db.session.rollback()
            print(f"列可能已存在: {e}")
        
        # 添加访客可见列
        try:
            db.session.execute('ALTER TABLE system_message ADD COLUMN guest_visible BOOLEAN DEFAULT 0')
            db.session.commit()
            print("成功添加 system_message.guest_visible 列")
        except Exception as e:
            db.session.rollback()
            print(f"列可能已存在: {e}")
        
    app.run(debug=True) 