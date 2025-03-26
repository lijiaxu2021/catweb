// 页面动画控制
document.addEventListener('DOMContentLoaded', function() {
    // 创建页面过渡元素
    const pageTransition = document.createElement('div');
    pageTransition.className = 'page-transition';
    document.body.appendChild(pageTransition);
    
    // 页面加载完成后淡出过渡效果
    setTimeout(() => {
        pageTransition.classList.add('hide');
        setTimeout(() => pageTransition.remove(), 1000);
    }, 500);
    
    // 处理链接点击的页面过渡，需要排除下拉菜单触发器
    document.addEventListener('click', e => {
        const link = e.target.closest('a');
        if (link && 
            link.href && 
            link.href.startsWith(window.location.origin) && 
            !link.hasAttribute('data-no-transition') && 
            !link.classList.contains('dropdown-toggle') && // 排除下拉菜单触发器
            !link.closest('.dropdown-menu')) { // 排除下拉菜单内部链接
            
            e.preventDefault();
            
            const newTransition = document.createElement('div');
            newTransition.className = 'page-transition';
            document.body.appendChild(newTransition);
            
            setTimeout(() => {
                window.location = link.href;
            }, 600);
        }
    });
    
    // 滚动动画
    const animateElements = document.querySelectorAll('.animate-on-scroll');
    
    function checkIfInView() {
        animateElements.forEach(element => {
            const rect = element.getBoundingClientRect();
            const windowHeight = window.innerHeight || document.documentElement.clientHeight;
            
            if (rect.top <= windowHeight * 0.85) {
                element.classList.add('visible');
            }
        });
    }
    
    // 初次检查
    checkIfInView();
    
    // 滚动时检查，增加节流函数
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(checkIfInView, 100);
    });
    
    // 添加涟漪效果到按钮
    const buttons = document.querySelectorAll('button, .btn');
    buttons.forEach(button => {
        if (!button.classList.contains('ripple')) {
            button.classList.add('ripple');
        }
    });
    
    // 卡片悬浮效果
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        if (!card.classList.contains('hover-float')) {
            card.classList.add('hover-float');
        }
    });
});

// 表单提交加载动画
document.addEventListener('submit', function(e) {
    const form = e.target;
    const submitButton = form.querySelector('button[type="submit"]');
    
    if (submitButton && !submitButton.classList.contains('loading')) {
        const originalText = submitButton.innerHTML;
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="loader-small"></span> 处理中...';
        submitButton.classList.add('loading');
        
        // 恢复按钮状态
        setTimeout(() => {
            if (submitButton.classList.contains('loading')) {
                submitButton.disabled = false;
                submitButton.innerHTML = originalText;
                submitButton.classList.remove('loading');
            }
        }, 10000); // 10秒超时
    }
});

// 基于滚动位置的渐进式动画
function updateScrollBasedAnimations() {
    const elements = document.querySelectorAll('.scroll-animate');
    const windowHeight = window.innerHeight;
    const scrollY = window.scrollY;
    
    elements.forEach(element => {
        const rect = element.getBoundingClientRect();
        const elementTop = rect.top + scrollY;
        const elementVisible = 150;
        
        // 计算元素在视窗中的位置百分比
        const scrollPercent = Math.min(
            Math.max(
                (windowHeight + scrollY - elementTop) / (windowHeight + rect.height) * 100, 
                0
            ), 
            100
        );
        
        // 应用基于滚动百分比的CSS变量
        element.style.setProperty('--scroll-percent', scrollPercent + '%');
        
        if (elementTop < (scrollY + windowHeight - elementVisible)) {
            element.classList.add('active');
        } else {
            element.classList.remove('active');
        }
    });
}

// 添加滚动监听
window.addEventListener('scroll', updateScrollBasedAnimations);
window.addEventListener('resize', updateScrollBasedAnimations);
document.addEventListener('DOMContentLoaded', updateScrollBasedAnimations); 