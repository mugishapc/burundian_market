// Enhanced form validation and image handling
document.addEventListener('DOMContentLoaded', function() {
    console.log('Script loaded - product images system');

    // Basic form validation
    const loginForm = document.querySelector("form[action='{{ url_for('login') }}']");
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const identifier = document.getElementById('identifier')?.value;
            const password = document.getElementById('password')?.value;
            
            if (!identifier || !password) {
                e.preventDefault();
                alert('Please fill in all fields');
            }
        });
    }
    
    // Register form validation
    const registerForm = document.querySelector("form[action='{{ url_for('register') }}']");

    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password')?.value;
            const phone = document.getElementById('phone')?.value;
            
            if (password && password.length < 6) {
                e.preventDefault();
                alert('Password must be at least 6 characters');
                return;
            }
        });
    }
    
    // Add product form validation
    const addProductForm = document.querySelector("form[action='{{ url_for('add_product') }}']");

    if (addProductForm) {
        addProductForm.addEventListener('submit', function(e) {
            const price = parseFloat(document.getElementById('price')?.value || 0);
            
            if (price <= 0) {
                e.preventDefault();
                alert('Price must be greater than 0');
            }
        });
    }
    
    // Enhanced image preview for product upload
    const imageInput = document.getElementById('image');
    if (imageInput) {
        imageInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Validate file type
                const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
                if (!validTypes.includes(file.type)) {
                    alert('Please select a valid image file (JPEG, PNG, GIF, WEBP)');
                    this.value = '';
                    return;
                }
                
                // Validate file size (max 5MB)
                if (file.size > 5 * 1024 * 1024) {
                    alert('Image size should be less than 5MB');
                    this.value = '';
                    return;
                }
                
                const reader = new FileReader();
                reader.onload = function(event) {
                    const preview = document.getElementById('image-preview');
                    if (!preview) {
                        const previewContainer = document.createElement('div');
                        previewContainer.className = 'mb-3';
                        previewContainer.id = 'image-preview-container';
                        
                        const previewTitle = document.createElement('p');
                        previewTitle.className = 'form-label';
                        previewTitle.textContent = 'Image Preview';
                        
                        const previewImg = document.createElement('img');
                        previewImg.id = 'image-preview';
                        previewImg.src = event.target.result;
                        previewImg.className = 'img-thumbnail';
                        previewImg.style.maxHeight = '200px';
                        previewImg.style.maxWidth = '100%';
                        
                        previewContainer.appendChild(previewTitle);
                        previewContainer.appendChild(previewImg);
                        
                        imageInput.parentNode.insertBefore(previewContainer, imageInput.nextSibling);
                    } else {
                        preview.src = event.target.result;
                    }
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Global image reload function
    window.reloadProductImages = function() {
        console.log('Reloading product images...');
        const productImages = document.querySelectorAll('img[src*="data:image"]');
        const timestamp = new Date().getTime();
        
        productImages.forEach(img => {
            if (img.src) {
                const originalSrc = img.src.split('?')[0];
                img.src = originalSrc + '?reload=' + timestamp;
            }
        });
    };
    
    // Auto-reload product images every 30 seconds
    setInterval(() => {
        if (document.visibilityState === 'visible') {
            window.reloadProductImages();
        }
    }, 30000);
    
    // Enhanced error handling for product images
    document.querySelectorAll('img[src*="data:image"]').forEach(img => {
        let retryCount = 0;
        const maxRetries = 3;
        
        img.addEventListener('error', function() {
            console.warn('Product image failed to load:', this.src.substring(0, 100));
            retryCount++;
            
            if (retryCount <= maxRetries) {
                // Try reloading with exponential backoff
                setTimeout(() => {
                    const currentSrc = this.src.split('?')[0];
                    this.src = currentSrc + '?retry=' + retryCount + '&t=' + new Date().getTime();
                }, 1000 * retryCount);
            } else {
                console.error('Product image failed after', maxRetries, 'attempts');
                // Hide image and show fallback
                this.style.display = 'none';
                const fallback = this.nextElementSibling;
                if (fallback && (fallback.classList.contains('no-image') || fallback.classList.contains('image-fallback'))) {
                    fallback.style.display = 'flex';
                }
            }
        });
        
        img.addEventListener('load', function() {
            console.log('Product image loaded successfully');
            retryCount = 0;
            // Hide fallback if image loads successfully
            const fallback = this.nextElementSibling;
            if (fallback && (fallback.classList.contains('no-image') || fallback.classList.contains('image-fallback'))) {
                fallback.style.display = 'none';
            }
        });
    });
    
    // Initial product image load assurance
    setTimeout(() => {
        window.reloadProductImages();
    }, 1000);
});