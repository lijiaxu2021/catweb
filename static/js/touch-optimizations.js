/**
 * 移动端触摸交互优化
 */
document.addEventListener('DOMContentLoaded', function() {
  // 检测是否为触摸设备
  const isTouchDevice = 'ontouchstart' in window || 
                        navigator.maxTouchPoints > 0 || 
                        navigator.msMaxTouchPoints > 0;
  
  if (isTouchDevice) {
    document.body.classList.add('touch-device');
    
    // 添加触摸反馈类
    const interactiveElements = document.querySelectorAll('a, button, .card, .nav-link, .btn');
    interactiveElements.forEach(el => {
      el.classList.add('touch-feedback');
    });
    
    // 优化下拉菜单
    optimizeDropdowns();
    
    // 添加滑动手势
    setupSwipeGestures();
    
    // 替换悬停状态为激活状态
    document.querySelectorAll('.hover-effect').forEach(el => {
      el.classList.remove('hover-effect');
      el.classList.add('touch-effect');
    });
  } else {
    document.body.classList.add('desktop-device');
    
    // 仅在桌面设备启用高级悬停效果
    document.querySelectorAll('.card').forEach(card => {
      card.classList.add('desktop-hover-3d');
    });
  }
  
  // 根据设备性能调整动画复杂度
  adjustAnimationsForDevicePerformance();
});

/**
 * 针对触摸设备优化下拉菜单
 */
function optimizeDropdowns() {
  const dropdownToggles = document.querySelectorAll('.dropdown-toggle');
  
  dropdownToggles.forEach(toggle => {
    // 第一次点击显示菜单，第二次才跳转
    toggle.addEventListener('click', function(e) {
      const dropdown = this.closest('.dropdown');
      const isOpen = dropdown.classList.contains('show');
      
      // 如果链接有href且下拉菜单已显示，则允许导航
      if (this.getAttribute('href') && this.getAttribute('href') !== '#' && isOpen) {
        return true;
      }
      
      // 否则显示下拉菜单并阻止导航
      e.preventDefault();
      e.stopPropagation();
      
      // 使用Bootstrap API切换下拉菜单
      const dropdownInstance = new bootstrap.Dropdown(toggle);
      if (isOpen) {
        dropdownInstance.hide();
      } else {
        dropdownInstance.show();
      }
    });
  });
}

/**
 * 设置滑动手势支持
 */
function setupSwipeGestures() {
  let touchStartX = 0;
  let touchEndX = 0;
  
  // 检测水平滑动手势
  document.addEventListener('touchstart', e => {
    touchStartX = e.changedTouches[0].screenX;
  }, {passive: true});
  
  document.addEventListener('touchend', e => {
    touchEndX = e.changedTouches[0].screenX;
    handleSwipeGesture();
  }, {passive: true});
  
  function handleSwipeGesture() {
    const swipeThreshold = 100; // 最小滑动距离
    
    // 向左滑动
    if (touchEndX < touchStartX - swipeThreshold) {
      // 检查是否在文章内并处理下一篇文章导航
      const nextPostLink = document.querySelector('.next-post-link');
      if (nextPostLink) {
        window.location.href = nextPostLink.getAttribute('href');
      }
    }
    
    // 向右滑动
    if (touchEndX > touchStartX + swipeThreshold) {
      // 检查是否在文章内并处理上一篇文章导航
      const prevPostLink = document.querySelector('.prev-post-link');
      if (prevPostLink) {
        window.location.href = prevPostLink.getAttribute('href');
      }
    }
  }
  
  // 为水平滚动容器添加触摸滑动支持
  const touchScrollContainers = document.querySelectorAll('.touch-scroll');
  touchScrollContainers.forEach(container => {
    let isDown = false;
    let startX;
    let scrollLeft;
    
    container.addEventListener('touchstart', e => {
      isDown = true;
      startX = e.touches[0].pageX - container.offsetLeft;
      scrollLeft = container.scrollLeft;
    }, {passive: true});
    
    container.addEventListener('touchend', () => {
      isDown = false;
    }, {passive: true});
    
    container.addEventListener('touchcancel', () => {
      isDown = false;
    }, {passive: true});
    
    container.addEventListener('touchmove', e => {
      if (!isDown) return;
      e.preventDefault();
      const x = e.touches[0].pageX - container.offsetLeft;
      const walk = (x - startX) * 2; // 滚动速度
      container.scrollLeft = scrollLeft - walk;
    });
  });
}

/**
 * 根据设备性能调整动画
 */
function adjustAnimationsForDevicePerformance() {
  // 简易设备性能检测
  const isLowPerformanceDevice = 
    /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) && 
    (navigator.hardwareConcurrency < 4 || navigator.deviceMemory < 4);
  
  if (isLowPerformanceDevice) {
    // 禁用或简化复杂动画
    document.body.classList.add('reduce-animations');
    
    // 减少或禁用3D变换
    document.querySelectorAll('.card-3d-effect').forEach(el => {
      el.classList.remove('card-3d-effect');
    });
    
    // 简化过渡效果
    document.querySelectorAll('.animate-on-scroll').forEach(el => {
      el.style.transition = 'all 0.2s ease';
    });
  }
}

/**
 * 添加响应式网格布局支持
 */
function setupResponsiveGrids() {
  const grids = document.querySelectorAll('.responsive-grid');
  
  function updateGrids() {
    grids.forEach(grid => {
      const minWidth = parseInt(grid.dataset.minWidth || '300');
      const gap = parseInt(grid.dataset.gap || '20');
      
      if (window.innerWidth < 768) {
        // 移动端显示为单列
        grid.style.gridTemplateColumns = '1fr';
      } else {
        // 平板和桌面端使用自适应网格
        grid.style.gridTemplateColumns = `repeat(auto-fill, minmax(${minWidth}px, 1fr))`;
      }
      
      grid.style.gap = `${gap}px`;
    });
  }
  
  updateGrids();
  window.addEventListener('resize', updateGrids);
}

// 初始化响应式网格
document.addEventListener('DOMContentLoaded', setupResponsiveGrids);

/**
 * 图像延迟加载与自适应处理
 */
function handleResponsiveImages() {
  // 使用Intersection Observer实现懒加载
  if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          const src = img.dataset.src;
          
          if (src) {
            img.src = src;
            img.removeAttribute('data-src');
          }
          
          observer.unobserve(img);
        }
      });
    });
    
    // 观察所有延迟加载的图像
    document.querySelectorAll('img[data-src]').forEach(img => {
      imageObserver.observe(img);
    });
  } else {
    // 回退方案：直接加载所有图像
    document.querySelectorAll('img[data-src]').forEach(img => {
      img.src = img.dataset.src;
    });
  }
}

// 初始化图像处理
document.addEventListener('DOMContentLoaded', handleResponsiveImages); 