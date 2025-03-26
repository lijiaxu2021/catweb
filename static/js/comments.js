// 评论提交处理
document.addEventListener('DOMContentLoaded', function() {
    const commentForm = document.getElementById('comment-form');
    if (commentForm) {
        commentForm.addEventListener('submit', function(e) {
            const contentField = document.getElementById('content');
            if (!contentField.value.trim()) {
                e.preventDefault();
                alert('评论内容不能为空');
                return false;
            }
        });
    }
    
    // 评论回复功能
    const replyButtons = document.querySelectorAll('.reply-button');
    replyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const commentId = this.getAttribute('data-comment-id');
            const commentUsername = this.getAttribute('data-username');
            const commentForm = document.getElementById('comment-form');
            const contentField = document.getElementById('content');
            
            // 设置回复提示
            contentField.value = `@${commentUsername} `;
            contentField.focus();
            
            // 滚动到评论表单
            commentForm.scrollIntoView({ behavior: 'smooth' });
        });
    });
}); 