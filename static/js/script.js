// Basic form validation
document.addEventListener('DOMContentLoaded', function() {
    console.log('Script loaded');

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
    
    // Image preview for product upload
    const imageInput = document.getElementById('image');
    if (imageInput) {
        imageInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
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
});