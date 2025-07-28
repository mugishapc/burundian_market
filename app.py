from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime
from sqlalchemy import or_
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask import abort
from datetime import datetime, timedelta
from flask import make_response
from sqlalchemy import func
from flask_migrate import Migrate

app = Flask(__name__)
csrf = CSRFProtect(app)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'd29c234ca310aa6990092d4b6cd4c4854585c51e1f73bf4de510adca03f5bc4e')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ('mugishapc1@gmail.com')
app.config['MAIL_PASSWORD'] = ('ovle ndkq vyfh jwxr')
app.config['MAIL_DEFAULT_SENDER'] = 'mugishapc1@gmail.com'
app.config['SECURITY_PASSWORD_SALT'] = ('SECURITY_PASSWORD_SALT', 'default-salt-for-dev')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Sessions last 1 day
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Refresh session with each request
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'


# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)
migrate = Migrate(app, db)

@app.before_request
def refresh_session():
    if 'user_id' in session:
        # Refresh session if it's about to expire
        session.modified = True
        
        # Check if user still exists
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        # Update session with current user data
        session['user_type'] = user.user_type
        session['username'] = user.username

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    user_type = db.Column(db.String(10), nullable=False)  # 'admin', 'seller', 'buyer'
    is_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    cookie_prefs = db.Column(db.String(200), nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    session_token = db.Column(db.String(255))



    # New fields for seller subscription
    is_seller_active = db.Column(db.Boolean, default=True)
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)
    last_payment_proof = db.Column(db.String(200), nullable=True)
    last_active = db.Column(db.DateTime, default=db.func.current_timestamp(), 
                           onupdate=db.func.current_timestamp())
    
    def is_active(self):
        """Check if user session should still be valid"""
        return datetime.now() - self.last_active < timedelta(hours=1)


    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=True)
    image = db.Column(db.String(200), nullable=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    seller = db.relationship('User', backref=db.backref('products', lazy=True))
    
    def __repr__(self):
        return f'<Product {self.title}>'

# Create tables

# Helper Functions
def send_verification_email(email, token):
    verify_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email Address', recipients=[email])
    msg.body = f'''Welcome to Burundian Market!
    
Please click the following link to verify your email address:
{verify_url}

If you did not create an account, please ignore this email.
'''
    mail.send(msg)

def send_password_reset_email(email, token):
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email.
'''
    mail.send(msg)

# Routes
@app.route('/')
def home():
    products = Product.query.join(User).filter(
        User.is_seller_active == True
    ).order_by(Product.created_at.desc()).limit(8).all()
    return render_template('index.html', products=products)

@app.route('/products/search')
def product_search():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 12  # Products per page

    # Base query - active sellers only
    products_query = Product.query.join(User).filter(
        User.is_seller_active == True
    )

    # Apply search query filter (searches across all categories)
    if query:
        products_query = products_query.filter(
            or_(
                Product.title.ilike(f'%{query}%'),
                Product.description.ilike(f'%{query}%'),
                Product.category.ilike(f'%{query}%')  # Also search in category names
            )
        )

    # Get all available categories (for dropdown/filter display)
    categories = db.session.query(
        Product.category.distinct().label('category')
    ).filter(
        Product.category.isnot(None)
    ).order_by(
        'category'
    ).all()
    categories = [c.category for c in categories if c.category]

    # Paginate and order results
    products = products_query.order_by(
        Product.created_at.desc()
    ).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    return render_template(
        'product_search.html',
        products=products,
        search_query=query,
        categories=categories,
        selected_category=None  # No category selected when doing general search
    )


# In app.py, update the register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form.get('phone')
        user_type = request.form['user_type']
        
        # Only check for username (email check removed)
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create user (email duplicates now allowed)
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            phone=phone,
            user_type=user_type
        )
        
        # For sellers, set the trial period
        if user_type == 'seller':
            new_user.is_seller_active = True  # Active during trial
            # subscription_start/end will be null during trial
        
        # Generate verification token
        token = serializer.dumps(email, salt='email-verification')
        new_user.verification_token = token
        
        db.session.add(new_user)
        db.session.commit()
        
        # Send verification email
        send_verification_email(new_user.email, token)
        
        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=3600)
    except:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first_or_404()
    
    if user.email_verified:
        flash('Account already verified. Please login.', 'info')
    else:
        user.email_verified = True
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Email verified successfully! You can now login.', 'success')
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()
        remember = 'remember' in request.form  # Check if "remember me" was checked

        if not identifier or not password:
            flash('Please enter both email/username and password', 'danger')
            return redirect(url_for('login'))

        user = db.session.query(User).filter(
            (func.lower(User.email) == func.lower(identifier)) | 
            (func.lower(User.username) == func.lower(identifier))
        ).first()

        if not user:
            flash('No account found with this email or username', 'danger')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Invalid password', 'danger')
            return redirect(url_for('login'))

        if not user.email_verified:
            flash('Please verify your email before logging in', 'warning')
            return redirect(url_for('login'))

        # Clear and create new session
        session.clear()
        session.permanent = True  # Make the session persistent
        session['user_id'] = user.id
        session['user_type'] = user.user_type
        session['username'] = user.username
        session['_fresh'] = True
        session.modified = True

        # Update last login time
        user.last_login = datetime.now()
        db.session.commit()

        flash('Login successful!', 'success')
        
        # Create response and set remember cookie if "remember me" was checked
        response = make_response(redirect(url_for(
            'admin_dashboard' if user.user_type == 'admin' else
            'seller_dashboard' if user.user_type == 'seller' else
            'buyer_dashboard'
        )))
        
        if remember:
            # Create a remember token and store it in the database
            remember_token = serializer.dumps(user.id, salt='remember-me')
            user.remember_token = remember_token
            db.session.commit()
            
            # Set the cookie
            response.set_cookie(
                'remember_token',
                value=remember_token,
                expires=datetime.now() + timedelta(days=30),
                httponly=True,
                secure=app.config['SESSION_COOKIE_SECURE'],
                samesite='Lax'
            )
        
        return response

    return render_template('login.html')

@app.before_request
def check_persistent_login():
    if 'user_id' not in session and request.endpoint != 'logout':
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            try:
                user_id = serializer.loads(remember_token, salt='remember-me')
                user = User.query.get(user_id)
                if user and user.remember_token == remember_token:
                    # Recreate the session
                    session.permanent = True
                    session['user_id'] = user.id
                    session['user_type'] = user.user_type
                    session['username'] = user.username
                    session['_fresh'] = False  # Not a fresh login
                    session.modified = True
                    
                    # Update last login time
                    user.last_login = datetime.now()
                    db.session.commit()
            except:
                # Token is invalid - clear the cookie
                pass


@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.remember_token = None
            db.session.commit()
    
    session.clear()
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('remember_token')
    flash('You have been logged out.', 'info')
    return response

@app.route('/seller/dashboard')
def seller_dashboard():
    if 'user_id' not in session or session['user_type'] != 'seller':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    products = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    return render_template('seller_dashboard.html', user=user, products=products)

@app.route('/buyer/dashboard')
def buyer_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    categories = db.session.query(Product.category.distinct()).filter(Product.category.isnot(None)).all()
    categories = [c[0] for c in categories if c[0]]
    
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('buyer_dashboard.html', products=products, categories=categories)

@app.route('/product/add', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session or session['user_type'] != 'seller':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form.get('category')
        
        # Handle image upload
        image = request.files.get('image')
        image_url = None
        
        if image and image.filename != '':
            # Create uploads folder if it doesn't exist
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            # Secure filename and save
            filename = f"product_{session['user_id']}_{len(Product.query.all()) + 1}.jpg"
            image_path = os.path.join(upload_folder, filename)
            image.save(image_path)
            image_url = f"uploads/{filename}"
        
        new_product = Product(
            title=title,
            description=description,
            price=price,
            category=category,
            image=image_url,
            seller_id=session['user_id']
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        flash('Product added successfully!', 'success')
        return redirect(url_for('seller_dashboard'))
    
    return render_template('add_product.html')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    seller = User.query.get(product.seller_id)
    
    # Check if the current user is the seller
    is_seller = 'user_id' in session and session['user_id'] == product.seller_id
    
    return render_template('product_detail.html', product=product, seller=seller, is_seller=is_seller)



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = serializer.dumps(email, salt='password-reset')
            send_password_reset_email(user.email, token)
        
        flash('If an account exists with that email, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user.password = generate_password_hash(password)
        db.session.commit()
        
        flash('Your password has been updated! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # Check if username is already taken by another user
        new_username = request.form.get('username')
        if new_username != user.username and User.query.filter_by(username=new_username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('edit_profile'))
        
        user.username = new_username
        user.phone = request.form.get('phone', user.phone)
        
        # Handle password change
        new_password = request.form.get('new_password')
        if new_password and len(new_password) >= 6:
            user.password = generate_password_hash(new_password)
        elif new_password:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('seller_dashboard' if user.user_type == 'seller' else 'buyer_dashboard'))
    
    return render_template('edit_profile.html', user=user)

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Delete all user's products first (if seller)
    if user.user_type == 'seller':
        Product.query.filter_by(seller_id=user.id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    # Clear session
    session.clear()
    flash('Your account has been permanently deleted', 'info')
    return redirect(url_for('home'))

@app.route('/product/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        abort(403)  # Forbidden for buyers
    
    product = Product.query.get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)  # Forbidden for other sellers
    
    if request.method == 'POST':
        product.title = request.form['title']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.category = request.form.get('category')
        
        # Handle image update
        image = request.files.get('image')
        if image and image.filename != '':
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            filename = f"product_{session['user_id']}_{product_id}.jpg"
            image_path = os.path.join(upload_folder, filename)
            image.save(image_path)
            product.image = f"uploads/{filename}"
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('seller_dashboard'))
    
    return render_template('edit_product.html', product=product)

@app.route('/product/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        abort(403)  # Forbidden for buyers
    
    product = Product.query.get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)  # Forbidden for other sellers
    
    # Delete product image if exists
    if product.image:
        try:
            os.remove(os.path.join(app.root_path, 'static', product.image))
        except:
            pass
    
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully', 'success')
    return redirect(url_for('seller_dashboard'))

# In app.py, add these new routes

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    # Get all users with their subscription status
    users = User.query.order_by(User.created_at.desc()).all()
    
    # Process sellers' subscription status
    ending_soon = []
    for user in users:
        if user.user_type == 'seller':
            if user.subscription_end:
                days_left = (user.subscription_end - datetime.now()).days
                user.days_left = days_left
                if 0 < days_left <= 5:
                    ending_soon.append(user)
            else:
                user.days_left = None
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         ending_soon=ending_soon,
                         datetime=datetime)

@app.route('/admin/user/<int:user_id>')
def admin_view_user(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    user = User.query.get_or_404(user_id)
    products = []
    images = []
    
    if user.user_type == 'seller':
        products = Product.query.filter_by(seller_id=user.id).all()
        # Get all images from products
        images = [product.image for product in products if product.image]
        
        # Calculate subscription status
        if user.subscription_end:
            days_left = (user.subscription_end - datetime.now()).days
            user.subscription_status = {
                'days_left': days_left,
                'active': days_left > 0 if days_left else False
            }
    
    return render_template('admin_user_detail.html', 
                         user=user, 
                         products=products,
                         images=images,
                         datetime=datetime)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    user = User.query.get_or_404(user_id)
    username = user.username
    
    try:
        # Delete user's products if they're a seller
        if user.user_type == 'seller':
            # First delete product images
            for product in user.products:
                if product.image:
                    try:
                        os.remove(os.path.join(app.root_path, 'static', product.image))
                    except:
                        pass
            Product.query.filter_by(seller_id=user.id).delete()
        
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} has been successfully deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting user {user_id}: {str(e)}")
        flash('Error deleting user. Please try again.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/seller/activate/<int:user_id>', methods=['POST'])
def admin_activate_seller(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    seller = User.query.get_or_404(user_id)
    if seller.user_type != 'seller':
        abort(400)
    
    try:
        days = int(request.form.get('days', 0))
        payment_proof = request.form.get('payment_proof', '')
        
        if days <= 0:
            flash('Invalid subscription period', 'danger')
            return redirect(url_for('admin_view_user', user_id=user_id))
        
        now = datetime.now()
        seller.subscription_start = now
        seller.subscription_end = now + timedelta(days=days)
        seller.is_seller_active = True
        seller.last_payment_proof = payment_proof
        
        db.session.commit()
        
        # Send notification email
        try:
            msg = Message(
                'Your Subscription Has Been Activated',
                recipients=[seller.email]
            )
            msg.body = f'''Hello {seller.username},
            
Your subscription has been activated for {days} days (until {seller.subscription_end.strftime('%B %d, %Y')}).
You can now publish your products on Burundian Market.

Thank you for using our service!
'''
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Error sending email to {seller.email}: {str(e)}")
        
        flash('Seller subscription activated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error activating seller subscription: {str(e)}")
        flash('Error activating subscription. Please try again.', 'danger')
    
    return redirect(url_for('admin_view_user', user_id=user_id))

@app.route('/admin/user/message/<int:user_id>', methods=['GET', 'POST'])
def admin_send_message(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        subject = request.form.get('subject', 'Message from Burundian Market Admin')
        message = request.form.get('message', '').strip()
        
        if not message:
            flash('Message cannot be empty', 'danger')
            return redirect(url_for('admin_send_message', user_id=user_id))
        
        try:
            # Send email
            msg = Message(subject, recipients=[user.email])
            msg.body = message
            mail.send(msg)
            
            flash('Message sent successfully!', 'success')
            return redirect(url_for('admin_view_user', user_id=user_id))
        except Exception as e:
            app.logger.error(f"Error sending message to {user.email}: {str(e)}")
            flash('Failed to send message. Please try again.', 'danger')
    
    return render_template('admin_send_message.html', user=user)
# In app.py, add these routes

# Seller Subscription Page
@app.route('/seller/subscribe')
def seller_subscribe():
    if 'user_id' not in session or session.get('user_type') != 'seller':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('seller_subscribe.html', user=user)

# Process Subscription Choice
@app.route('/seller/choose-subscription', methods=['POST'])
def choose_subscription():
    if 'user_id' not in session or session.get('user_type') != 'seller':
        return redirect(url_for('login'))
    
    period = request.form.get('period')
    periods = {
        '30': 15000,
        '60': 30000,
        '120': 60000,
        '180': 75000,
        '250': 90000,
        '300': 120000,
        '365': 155000
    }
    
    if period not in periods:
        flash('Invalid subscription period selected', 'danger')
        return redirect(url_for('seller_subscribe'))
    
    return render_template('subscription_payment.html', 
                         period=period,
                         amount=periods[period],
                         days=period)

# Middleware to check seller subscription status
@app.before_request
def check_seller_subscription():
    # Only proceed if user is logged in as a seller
    if 'user_id' not in session or session.get('user_type') != 'seller':
        return
    
    try:
        user = User.query.get(session['user_id'])
        
        # Check if user exists
        if user is None:
            session.clear()  # Clear invalid session
            flash('User not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        # If seller's trial period is over (5 days)
        if user.is_seller_active and user.subscription_end is None:
            trial_end = user.created_at + timedelta(days=5)
            if datetime.now() > trial_end:
                user.is_seller_active = False
                db.session.commit()

                # Notify seller
                msg = Message('Your Trial Period Has Ended', recipients=[user.email])
                msg.body = f'''Hello {user.username},
                
Your 5-day trial period has ended. To continue publishing products, please subscribe to one of our plans.

Thank you for using Burundian Market!
'''
                mail.send(msg)
                
                # Notify admin
                msg = Message('Seller Trial Period Ended', recipients=['mugishapc1@gmail.com'])
                msg.body = f'''Admin,
                
Seller {user.username} (ID: {user.id}) has ended their trial period and needs to subscribe.
'''
                mail.send(msg)
        
        # If subscription is ending in 5 days
        elif user.is_seller_active and user.subscription_end:
            days_left = (user.subscription_end - datetime.now()).days
            if days_left == 5:
                # Notify seller
                msg = Message('Your Subscription is Ending Soon', recipients=[user.email])
                msg.body = f'''Hello {user.username},
                
Your subscription will end in 5 days. Please renew to avoid service interruption.

Thank you for using Burundian Market!
'''
                mail.send(msg)
                
                # Notify admin
                msg = Message('Seller Subscription Ending Soon', recipients=['mugishapc1@gmail.com'])
                msg.body = f'''Admin,
                
Seller {user.username} (ID: {user.id}) has only 5 days left in their subscription.
'''
                mail.send(msg)
        
        # Redirect to subscription page if not active
        if not user.is_seller_active and request.endpoint not in ['seller_subscribe', 'choose_subscription', 'logout', 'static']:
            flash('Your seller account is not active. Please subscribe to continue.', 'warning')
            return redirect(url_for('seller_subscribe'))
            
    except Exception as e:
        app.logger.error(f"Error in check_seller_subscription: {str(e)}")
        # Don't interrupt the request flow for minor errors
        return

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

# Add this with your other routes
@app.route('/cookie-preferences', methods=['GET', 'POST'])
def cookie_preferences():
    if request.method == 'POST':
        response = make_response(redirect(url_for('home')))
        
        # Set cookie preferences
        analytics = request.form.get('analytics', 'off')
        functional = request.form.get('functional', 'off')
        
        response.set_cookie(
            'cookie_preferences',
            value=f'analytics:{analytics}|functional:{functional}',
            expires=datetime.now() + timedelta(days=365),  # Now using datetime correctly
            httponly=True,
            samesite='Lax'
        )
        
        flash('Your cookie preferences have been saved', 'success')
        return response
    
    # Get current preferences
    preferences = {
        'analytics': 'off',
        'functional': 'off'
    }
    
    cookie_prefs = request.cookies.get('cookie_preferences')
    if cookie_prefs:
        for pref in cookie_prefs.split('|'):
            key, value = pref.split(':')
            preferences[key] = value
    
    return render_template('cookie_preferences.html', preferences=preferences)


 #Add these new categories (update your cookie_preferences route accordingly)
COOKIE_CATEGORIES = {
    'essential': {'required': True, 'description': 'Necessary for basic functionality'},
    'functional': {'required': False, 'description': 'Enhances user experience'},
    'analytics': {'required': False, 'description': 'Website usage analytics'},
    'marketing': {'required': False, 'description': 'Personalized ads and content'}
}

@app.route('/keepalive', methods=['POST'])
def keepalive():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.last_activity = datetime.utcnow()
            db.session.commit()
            return {'status': 'active'}, 200
    return {'status': 'inactive'}, 401

@app.route('/checksession')
def check_session():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and (datetime.utcnow() - user.last_activity).total_seconds() < 3600:  # 1 hour
            return {'status': 'active'}, 200
    return {'status': 'expired'}, 401

@app.route('/terms')
def terms():
    return render_template('terms.html', now=datetime.now())


if __name__ == '__main__':
    app.run(debug=True)