from app import app, db, User, Post, Comment, post_likes
import os
from sqlalchemy import text

# 强制使用正确的初始化顺序
def fix_models():
    with app.app_context():
        # 1. 删除旧的关系定义(不会影响数据库中的实际数据)
        if hasattr(User, 'liked_posts'):
            delattr(User, 'liked_posts')
        if hasattr(Post, 'likes'):
            delattr(Post, 'likes')
            
        # 2. 确保表存在 - 使用text()函数包装SQL
        db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS post_likes (
            post_id INTEGER NOT NULL, 
            user_id INTEGER NOT NULL,
            PRIMARY KEY (post_id, user_id),
            FOREIGN KEY(post_id) REFERENCES post (id),
            FOREIGN KEY(user_id) REFERENCES user (id)
        )
        """))
        db.session.commit()
        
        # 3. 重新定义关系(使用明确定义而非动态)
        User.liked_posts = db.relationship('Post', 
                                          secondary='post_likes',
                                          primaryjoin="User.id==post_likes.c.user_id",
                                          secondaryjoin="Post.id==post_likes.c.post_id",
                                          backref=db.backref('likes', lazy='dynamic'),
                                          lazy='dynamic')
        
        print("数据库关系修复完成!")
        
if __name__ == "__main__":
    fix_models() 