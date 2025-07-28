// Basic form validation
document.addEventListener('DOMContentLoaded', function() {
    // Lconst loginForm = document.querySelector("form[action='{{ url_for('login') }}']");
    const loginForm = document.querySelector("form[action='{{ url_for('login') }}']");

    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            if (!email || !password) {
                e.preventDefault();
                alert('Please fill in all fields');
            }
        });
    }
    
    // Register form validation
    const registerForm = document.querySelector("form[action='{{ url_for('register') }}']");

    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const phone = document.getElementById('phone').value;
            
            if (password.length < 6) {
                e.preventDefault();
                alert('Password must be at least 6 characters');
                return;
            }
            
            // Basic phone number validation for Burundi (257 country code)
            if (!phone.match(/^257\d{8}$/)) {
                e.preventDefault();
                alert('Please enter a valid Burundi phone number starting with 257');
            }
        });
    }
    
    // Add product form validation
    const addProductForm = document.querySelector("form[action='{{ url_for('add_product') }}']");

    if (addProductForm) {
        addProductForm.addEventListener('submit', function(e) {
            const price = parseFloat(document.getElementById('price').value);
            
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


// Initialize cookies based on preferences
function initCookies(prefsString) {
    const prefs = {};
    prefsString.split('|').forEach(pair => {
        const [key, value] = pair.split(':');
        prefs[key] = value;
    });

    if (prefs.analytics === 'on') {
        loadAnalytics();
    }
}

// Load analytics scripts
function loadAnalytics() {
    // Add your analytics scripts here
    console.log('Analytics cookies accepted - loading tracking scripts');
    // Example: Google Analytics, Facebook Pixel, etc.
}

// Check if analytics should be loaded
function shouldLoadAnalytics() {
    const cookiePrefs = getCookie('cookie_preferences');
    if (!cookiePrefs) return false;
    
    const prefs = {};
    cookiePrefs.split('|').forEach(pair => {
        const [key, value] = pair.split(':');
        prefs[key] = value;
    });
    
    return prefs.analytics === 'on';
}

// Get cookie value by name
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", function() {
    // Check if cookie consent is needed
    if (!localStorage.getItem('cookieConsent') && !getCookie('cookie_preferences')) {
        document.getElementById('cookieConsent').style.display = 'block';
    }
    
    // Handle accept all cookies
    document.getElementById('acceptCookies')?.addEventListener('click', function() {
        localStorage.setItem('cookieConsent', 'true');
        document.cookie = "cookie_preferences=analytics:on|functional:on; path=/; max-age=31536000; samesite=Lax";
        document.getElementById('cookieConsent').style.display = 'none';
        loadAnalytics();
    });
    
    // Initialize based on existing preferences
    const cookiePrefs = getCookie('cookie_preferences');
    if (cookiePrefs) {
        initCookies(cookiePrefs);
    }
});