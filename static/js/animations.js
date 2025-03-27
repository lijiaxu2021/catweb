// 页面动画控制
document.addEventListener('DOMContentLoaded', () => {
    // 添加页面加载动画
    const loadingOverlay = document.createElement('div');
    loadingOverlay.className = 'loading-overlay';
    loadingOverlay.innerHTML = '<div class="spinner"></div>';
    document.body.appendChild(loadingOverlay);
    
    // 1秒后移除加载动画
    setTimeout(() => {
        loadingOverlay.style.opacity = '0';
        setTimeout(() => loadingOverlay.remove(), 500);
        
        // 执行卡片发牌动画
        animatePostCards();
        
        // 执行其他元素的进入动画
        animateElementsOnScroll();
    }, 800);
    
    // 设置滚动监听
    setupScrollAnimations();
});

// 卡片发牌动画
function animatePostCards() {
    const postCards = document.querySelectorAll('.post-card');
    
    postCards.forEach((card, index) => {
        setTimeout(() => {
            card.style.opacity = '1';
            card.style.transform = 'translateY(0) rotate(0)';
        }, 100 + (index * 120)); // 错开时间，产生发牌效果
    });
}

// 滚动时的元素动画
function setupScrollAnimations() {
    // 使用 Intersection Observer API 检测元素是否进入视口
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            // 当元素进入视口时
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                observer.unobserve(entry.target); // 只动画一次
            }
        });
    }, {
        root: null, // 相对于视口
        threshold: 0.15, // 元素至少有15%在视口中可见
        rootMargin: '0px 0px -100px 0px' // 视口底部偏移，提前触发动画
    });
    
    // 观察所有需要动画的元素
    document.querySelectorAll('.animate-on-scroll').forEach(el => {
        observer.observe(el);
    });
}

// 页面中其他元素的动画
function animateElementsOnScroll() {
    const animateElements = document.querySelectorAll('.animate-on-scroll');
    
    animateElements.forEach((element, index) => {
        // 添加初始样式
        element.style.opacity = '0';
        element.style.transform = 'translateY(30px)';
        element.style.transition = `all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) ${index * 0.1}s`;
        
        // 设置动画类，触发动画
        setTimeout(() => {
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }, 100 + (index * 100));
    });
}

// 添加卡片悬停效果
document.addEventListener('mouseover', (e) => {
    const card = e.target.closest('.card');
    if (card) {
        // 为悬停的卡片添加特殊效果
        card.style.transform = 'translateY(-10px) scale(1.02)';
        card.style.boxShadow = '0 20px 30px rgba(0, 0, 0, 0.1)';
    }
});

document.addEventListener('mouseout', (e) => {
    const card = e.target.closest('.card');
    if (card) {
        // 还原卡片效果
        card.style.transform = 'translateY(-5px)';
        card.style.boxShadow = '0 10px 20px rgba(0, 0, 0, 0.08)';
    }
});

// 添加平滑滚动
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;
        
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop - 100,
                behavior: 'smooth'
            });
        }
    });
});

// 3D卡片效果
document.addEventListener('mousemove', function(e) {
    const cards = document.querySelectorAll('.card-3d-effect');
    
    cards.forEach(card => {
        // 获取卡片相对于视口的位置
        const rect = card.getBoundingClientRect();
        // 计算鼠标在卡片上的位置(相对于卡片中心)
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;
        
        // 旋转角度(根据鼠标位置计算)
        const rotateX = (y / rect.height * 20).toFixed(2); // 最大20度
        const rotateY = (x / rect.width * -20).toFixed(2); // 最大20度
        
        // 应用变换
        card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    });
});

// 重置3D效果
document.addEventListener('mouseleave', function() {
    const cards = document.querySelectorAll('.card-3d-effect');
    
    cards.forEach(card => {
        card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0)';
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