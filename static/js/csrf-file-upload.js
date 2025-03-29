/**
 * 处理文件上传表单的CSRF刷新
 * 在选择文件后和提交前自动刷新CSRF令牌
 */
document.addEventListener('DOMContentLoaded', function() {
    // 查找所有包含文件上传的表单
    const fileUploadForms = document.querySelectorAll('form[enctype="multipart/form-data"]');
    
    fileUploadForms.forEach(function(form) {
        // 查找表单中的文件输入和CSRF令牌输入
        const fileInputs = form.querySelectorAll('input[type="file"]');
        const csrfInput = form.querySelector('input[name="csrf_token"]');
        
        if (fileInputs.length > 0 && csrfInput) {
            // 文件选择时刷新CSRF令牌
            fileInputs.forEach(function(fileInput) {
                fileInput.addEventListener('change', function() {
                    if (this.files.length > 0) {
                        refreshCSRFToken(csrfInput);
                    }
                });
            });
            
            // 表单提交前刷新CSRF令牌
            form.addEventListener('submit', function(e) {
                // 检查是否有文件选择
                let hasFiles = false;
                fileInputs.forEach(function(input) {
                    if (input.files && input.files.length > 0) {
                        hasFiles = true;
                    }
                });
                
                if (hasFiles) {
                    e.preventDefault();
                    refreshCSRFToken(csrfInput, function() {
                        // 令牌刷新后提交表单
                        form.submit();
                    });
                }
            });
        }
    });
    
    // 刷新CSRF令牌的函数
    function refreshCSRFToken(tokenInput, callback) {
        fetch('/refresh-csrf-token')
            .then(response => response.json())
            .then(data => {
                tokenInput.value = data.csrf_token;
                if (typeof callback === 'function') {
                    callback();
                }
            })
            .catch(error => {
                console.error('刷新CSRF令牌失败:', error);
                // 即使失败也调用回调，避免表单被永久阻止提交
                if (typeof callback === 'function') {
                    callback();
                }
            });
    }
}); 