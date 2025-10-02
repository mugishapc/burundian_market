// Mobile-optimized form validation and image handling
document.addEventListener('DOMContentLoaded', function() {
    console.log('Mobile-optimized script loaded');

    // Mobile-optimized form validation
    const loginForm = document.querySelector("form[action='{{ url_for('login') }}']");
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const identifier = document.getElementById('identifier')?.value;
            const password = document.getElementById('password')?.value;
            
            if (!identifier || !password) {
                e.preventDefault();
                showMobileAlert('Please fill in all fields');
            }
        });
    }
    
    // Mobile-optimized register form validation
    const registerForm = document.querySelector("form[action='{{ url_for('register') }}']");

    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password')?.value;
            const phone = document.getElementById('phone')?.value;
            
            if (password && password.length < 6) {
                e.preventDefault();
                showMobileAlert('Password must be at least 6 characters');
                return;
            }
            
            // Mobile-optimized phone validation
            if (phone && !isValidPhone(phone)) {
                e.preventDefault();
                showMobileAlert('Please enter a valid phone number');
                return;
            }
        });
    }
    
    // Mobile-optimized add product form validation
    const addProductForm = document.querySelector("form[action='{{ url_for('add_product') }}']");

    if (addProductForm) {
        addProductForm.addEventListener('submit', function(e) {
            const price = parseFloat(document.getElementById('price')?.value || 0);
            
            if (price <= 0) {
                e.preventDefault();
                showMobileAlert('Price must be greater than 0');
            }
        });
    }
    
    // Mobile-optimized image preview for product upload
    const imageInput = document.getElementById('image');
    if (imageInput) {
        imageInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Mobile-optimized file validation
                const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
                if (!validTypes.includes(file.type)) {
                    showMobileAlert('Please select a valid image file (JPEG, PNG, GIF, WEBP)');
                    this.value = '';
                    return;
                }
                
                // Mobile-optimized file size (smaller for mobile)
                if (file.size > 3 * 1024 * 1024) {
                    showMobileAlert('Image size should be less than 3MB for mobile');
                    this.value = '';
                    return;
                }
                
                const reader = new FileReader();
                reader.onload = function(event) {
                    const preview = document.getElementById('image-preview');
                    if (!preview) {
                        createMobileImagePreview(event.target.result);
                    } else {
                        preview.src = event.target.result;
                    }
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Mobile-optimized global image reload function
    window.reloadProductImages = function() {
        console.log('Mobile: Reloading product images...');
        const productImages = document.querySelectorAll('img[src*="data:image"]');
        const timestamp = new Date().getTime();
        
        productImages.forEach(img => {
            if (img.src) {
                const originalSrc = img.src.split('?')[0];
                img.src = originalSrc + '?mobile_reload=' + timestamp;
            }
        });
    };
    
    // Mobile-optimized auto-reload (less frequent to save data)
    setInterval(() => {
        if (document.visibilityState === 'visible') {
            window.reloadProductImages();
        }
    }, 45000); // 45 seconds instead of 30
    
    // Mobile-optimized error handling for product images
    document.querySelectorAll('img[src*="data:image"]').forEach(img => {
        let retryCount = 0;
        const maxRetries = 2; // Less retries on mobile
        
        img.addEventListener('error', function() {
            console.warn('Mobile: Product image failed to load');
            retryCount++;
            
            if (retryCount <= maxRetries) {
                // Mobile-optimized backoff
                setTimeout(() => {
                    const currentSrc = this.src.split('?')[0];
                    this.src = currentSrc + '?mobile_retry=' + retryCount + '&t=' + new Date().getTime();
                }, 1500 * retryCount);
            } else {
                console.error('Mobile: Product image failed after', maxRetries, 'attempts');
                this.style.display = 'none';
                const fallback = this.nextElementSibling;
                if (fallback && (fallback.classList.contains('no-image') || fallback.classList.contains('image-fallback'))) {
                    fallback.style.display = 'flex';
                }
            }
        });
        
        img.addEventListener('load', function() {
            console.log('Mobile: Product image loaded successfully');
            retryCount = 0;
            const fallback = this.nextElementSibling;
            if (fallback && (fallback.classList.contains('no-image') || fallback.classList.contains('image-fallback'))) {
                fallback.style.display = 'none';
            }
        });
    });
    
    // Mobile-optimized initial image load
    setTimeout(() => {
        window.reloadProductImages();
    }, 1500);
    
    // Mobile-specific touch improvements
    initializeMobileTouch();
});

// Mobile-optimized helper functions
function showMobileAlert(message) {
    // Use native alert for mobile or create a mobile-friendly one
    if ('ontouchstart' in window) {
        alert(message);
    } else {
        // Create a mobile-friendly alert
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-warning alert-dismissible fade show position-fixed';
        alertDiv.style.cssText = 'top: 20px; left: 50%; transform: translateX(-50%); z-index: 9999; max-width: 90%;';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        document.body.appendChild(alertDiv);
        
        setTimeout(() => {
            alertDiv.remove();
        }, 3000);
    }
}

function isValidPhone(phone) {
    // Basic phone validation for mobile
    const phoneRegex = /^[\+]?[0-9\s\-\(\)]{10,}$/;
    return phoneRegex.test(phone);
}

function createMobileImagePreview(imageData) {
    const previewContainer = document.createElement('div');
    previewContainer.className = 'mb-3';
    previewContainer.id = 'image-preview-container';
    
    const previewTitle = document.createElement('p');
    previewTitle.className = 'form-label small';
    previewTitle.textContent = 'Image Preview';
    
    const previewImg = document.createElement('img');
    previewImg.id = 'image-preview';
    previewImg.src = imageData;
    previewImg.className = 'img-thumbnail';
    previewImg.style.maxHeight = '150px'; // Smaller for mobile
    previewImg.style.maxWidth = '100%';
    previewImg.style.display = 'block';
    previewImg.style.margin = '0 auto';
    
    previewContainer.appendChild(previewTitle);
    previewContainer.appendChild(previewImg);
    
    const imageInput = document.getElementById('image');
    imageInput.parentNode.insertBefore(previewContainer, imageInput.nextSibling);
}

function initializeMobileTouch() {
    // Improve touch experience
    document.querySelectorAll('a, button').forEach(element => {
        element.style.webkitTapHighlightColor = 'transparent';
    });
    
    // Prevent double-tap zoom
    let lastTouchEnd = 0;
    document.addEventListener('touchend', function (event) {
        const now = (new Date()).getTime();
        if (now - lastTouchEnd <= 300) {
            event.preventDefault();
        }
        lastTouchEnd = now;
    }, false);
    
    // Better scrolling on mobile
    document.documentElement.style.scrollBehavior = 'smooth';
}

// Mobile-optimized image lazy loading
if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.classList.remove('lazy');
                imageObserver.unobserve(img);
            }
        });
    });

    document.querySelectorAll('img.lazy').forEach(img => {
        imageObserver.observe(img);
    });
}

// Mobile network status detection
window.addEventListener('online', function() {
    showMobileAlert('Connection restored');
    window.reloadProductImages();
});

window.addEventListener('offline', function() {
    showMobileAlert('You are currently offline');
});

// Mobile-optimized resize handler
let resizeTimeout;
window.addEventListener('resize', function() {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(function() {
        // Adjust layout for mobile orientation changes
        if (window.innerHeight > window.innerWidth) {
            // Portrait mode
            document.body.classList.add('portrait');
            document.body.classList.remove('landscape');
        } else {
            // Landscape mode
            document.body.classList.add('landscape');
            document.body.classList.remove('portrait');
        }
    }, 250);
});