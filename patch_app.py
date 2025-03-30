def patch_post_route():
    """修补post路由函数，确保所有属性在使用前都经过空值检查"""
    print("正在应用post路由补丁...")
    
    # 导入必要的模块
    from app import app, Post, Category, Comment, session, request, redirect, url_for, flash, render_template, log_activity
    from sqlalchemy.sql import func
    
    # 定义新的路由处理函数
    def patched_post(slug):
        # 获取文章
        post = Post.query.filter_by(slug=slug).first_or_404()
        
        # 检查文章的featured_image是否为None，如果是则设置默认值
        if post.featured_image is None:
            post.featured_image = 'default_post.jpg'
        
        # 检查文章的background_image是否为None
        if post.background_image is None:
            post.background_image = ''
            
        # 增加浏览量
        post.views += 1
        db.session.commit()
        
        # 检查文章分类是否存在，如果不存在则使用默认分类
        if post.category is None:
            # 这里可以找到默认分类或创建一个
            default_category = Category.query.first()
            if default_category is None:
                default_category = Category(name="未分类", slug="uncategorized")
                db.session.add(default_category)
                db.session.commit()
            post.category_id = default_category.id
            db.session.commit()
        
        # 检查作者是否存在
        if post.author is None:
            flash('此文章作者信息不存在', 'warning')
            # 可以重定向到首页或处理缺失作者的情况
            return redirect(url_for('index'))
        
        # 获取相关评论
        comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.created_at.desc()).all()
        
        # 获取相关文章
        if post.category:
            related_posts = Post.query.filter(Post.category_id==post.category_id, 
                                             Post.id!=post.id).order_by(
                                             func.random()).limit(3).all()
        else:
            related_posts = []
        
        # 获取文章的附件
        attachments = []
        try:
            attachments = post.attachments
        except:
            # 如果获取附件出错，使用空列表
            pass
        
        # 记录日志 - 修正参数数量
        log_activity('article', 'view', f"查看文章: {post.title}")
        
        return render_template('post.html', post=post, comments=comments, 
                              related_posts=related_posts, attachments=attachments)
    
    # 替换应用中的路由
    for rule in app.url_map.iter_rules():
        if rule.endpoint == 'post' and '<slug>' in rule.rule:
            # 保存原函数
            original = app.view_functions['post']
            # 替换为新函数
            app.view_functions['post'] = patched_post
            print("post路由函数已成功修补")
            break
    
    return True

def patch_log_activity():
    """修补log_activity函数，使用db_direct代替ORM"""
    print("正在应用log_activity补丁...")
    
    # 导入必要的模块
    from app import app
    import db_direct
    
    # 定义新的log_activity函数
    def patched_log_activity(log_type, action, message=None):
        """使用直接数据库访问记录日志"""
        try:
            # 获取当前用户ID和IP地址
            from flask import session, request
            user_id = session.get('user_id')
            ip_address = request.remote_addr
            
            # 使用db_direct而非ORM模型
            result = db_direct.add_log(log_type, action, message, user_id, ip_address)
            return result
        except Exception as e:
            print(f"记录日志时出错: {e}")
            return False
    
    # 替换应用中的函数
    from app import log_activity
    import app as app_module
    
    # 保存原函数以供参考
    app_module._original_log_activity = log_activity
    
    # 替换为新函数
    app_module.log_activity = patched_log_activity
    
    print("log_activity函数已被成功修补")
    return True 

def patch_all():
    """应用所有补丁"""
    patches = [
        patch_log_activity,
        patch_request_handlers,
        patch_login_system,
        patch_post_route,  # 添加新的补丁函数
    ]
    
    for patch_func in patches:
        try:
            patch_func()
        except Exception as e:
            print(f"应用补丁时出错 ({patch_func.__name__}): {e}")
    
    print("所有补丁已完成") 