from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime
from sqlalchemy import or_, func, text
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask import abort
from datetime import datetime, timedelta
from dotenv import load_dotenv
import threading
import time
import smtplib
import urllib.parse

# Load environment variables first
load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)

# Configuration - Using environment variables properly
app.secret_key = os.environ.get('SECRET_KEY', 'd29c234ca310aa6990092d4b6cd4c4854585c51e1f73bf4de510adca03f5bc4e')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

# Email Configuration with timeout
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_TIMEOUT'] = 30  # 30 seconds timeout

# Security Configuration
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'default-salt-for-dev')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'

# Initialize extensions (NO MIGRATE!)
db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

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
    remember_token = db.Column(db.String(255))

    # New fields for seller subscription
    is_seller_active = db.Column(db.Boolean, default=True)
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)
    last_payment_proof = db.Column(db.String(200), nullable=True)
    last_active = db.Column(db.DateTime, default=db.func.current_timestamp(), 
                           onupdate=db.func.current_timestamp())
    
    # New field for subscription notifications
    last_notification_sent = db.Column(db.DateTime, nullable=True)
    
    def is_active(self):
        """Check if user session should still be valid"""
        return datetime.now() - self.last_active < timedelta(hours=1)

    def get_subscription_status(self):
        """Get subscription status with days left"""
        if not self.subscription_end:
            if self.is_seller_active:
                # Trial period
                trial_end = self.created_at + timedelta(days=5)
                days_left = (trial_end - datetime.now()).days
                return {
                    'status': 'trial',
                    'days_left': max(0, days_left),
                    'active': days_left > 0
                }
            else:
                return {'status': 'inactive', 'days_left': 0, 'active': False}
        else:
            days_left = (self.subscription_end - datetime.now()).days
            return {
                'status': 'subscription',
                'days_left': max(0, days_left),
                'active': days_left > 0 and self.is_seller_active
            }

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

# IMPROVED DATABASE INITIALIZATION - Handles schema updates
def initialize_database():
    """Initialize database tables and handle schema updates"""
    with app.app_context():
        try:
            print("🚀 Initializing database...")
            
            # Check if tables exist and handle schema updates
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if 'users' in existing_tables:
                print("ℹ️  Tables already exist, checking for schema updates...")
                
                # Check if last_notification_sent column exists
                users_columns = [col['name'] for col in inspector.get_columns('users')]
                
                if 'last_notification_sent' not in users_columns:
                    print("🔄 Adding missing column: last_notification_sent")
                    try:
                        # Add the missing column using raw SQL
                        with db.engine.connect() as conn:
                            conn.execute(text('ALTER TABLE users ADD COLUMN last_notification_sent TIMESTAMP'))
                            conn.commit()
                        print("✅ Added last_notification_sent column")
                    except Exception as e:
                        print(f"⚠️  Could not add column: {e}")
                        # Continue anyway - the app will work without the new column
                
                # Create admin user if not exists - using safer approach
                try:
                    admin_user = db.session.query(User).filter_by(email='mpc0679@gmail.com').first()
                    if not admin_user:
                        admin = User(
                            username='TEAM MANAGEMENT',
                            email='mpc0679@gmail.com',
                            password=generate_password_hash('61Mpc588214#'),
                            user_type='admin',
                            is_verified=True,
                            email_verified=True
                        )
                        db.session.add(admin)
                        db.session.commit()
                        print("✅ Admin user created")
                    else:
                        print("✅ Admin user already exists")
                except Exception as e:
                    print(f"⚠️  Could not create/administer admin user: {e}")
                
            else:
                # Create all tables if they don't exist
                print("🆕 Creating all tables...")
                db.create_all()
                print("✅ Created all tables")
                
                # Create admin user
                try:
                    admin = User(
                        username='TEAM MANAGEMENT',
                        email='mpc0679@gmail.com',
                        password=generate_password_hash('61Mpc588214#'),
                        user_type='admin',
                        is_verified=True,
                        email_verified=True
                    )
                    db.session.add(admin)
                    db.session.commit()
                    print("✅ Admin user created")
                except Exception as e:
                    print(f"⚠️  Could not create admin user: {e}")
            
            print("🎉 Database initialized successfully!")
            
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            import traceback
            traceback.print_exc()
            # Don't exit - let the app continue running

# Initialize database when app starts
initialize_database()

# Asynchronous Email Functions
def send_async_email(app, msg, max_retries=3):
    """Send email in background thread with retry logic"""
    def send_with_retry():
        for attempt in range(max_retries):
            try:
                with app.app_context():
                    mail.send(msg)
                print(f"✅ Email sent successfully (attempt {attempt + 1})")
                break
            except smtplib.SMTPException as e:
                print(f"❌ Email attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"❌ Failed to send email after {max_retries} attempts: {e}")
            except Exception as e:
                print(f"❌ Unexpected email error (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    print(f"❌ Final email failure after {max_retries} attempts: {e}")
    
    # Start the email sending in background thread
    thread = threading.Thread(target=send_with_retry)
    thread.daemon = True
    thread.start()

def send_verification_email(email, token):
    """Send email verification asynchronously"""
    verify_url = url_for('verify_email', token=token, _external=True)
    msg = Message(
        'Verify Your Email Address', 
        recipients=[email],
        body=f'''Welcome to Burundian Market!
    
Please click the following link to verify your email address:
{verify_url}

If you did not create an account, please ignore this email.
'''
    )
    send_async_email(app, msg)

def send_password_reset_email(email, token):
    """Send password reset email asynchronously"""
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message(
        'Password Reset Request', 
        recipients=[email],
        body=f'''To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email.
'''
    )
    send_async_email(app, msg)

def send_notification_email(recipient, subject, body):
    """Send general notification email asynchronously"""
    msg = Message(subject, recipients=[recipient], body=body)
    send_async_email(app, msg)

# Subscription Notification System
def notify_subscription_status(user, notification_type):
    """Notify user about subscription status with multiple fallback methods"""
    try:
        status = user.get_subscription_status()
        
        # Prevent spam - don't send same notification more than once per day
        if hasattr(user, 'last_notification_sent') and user.last_notification_sent and (datetime.now() - user.last_notification_sent).days < 1:
            return
        
        if notification_type == 'trial_ending':
            message = f'''
Hello {user.username},

Your 5-day trial period ends in {status['days_left']} days. 
To continue selling on Burundian Market, please subscribe to one of our plans.

Visit: https://burundian-market-e8vg.onrender.com/seller/subscribe

Thank you for using our service!
'''
            subject = 'Trial Period Ending Soon'
            
        elif notification_type == 'subscription_ending':
            message = f'''
Hello {user.username},

Your subscription will end in {status['days_left']} days.
Please renew your subscription to avoid service interruption.

Visit: https://burundian-market-e8vg.onrender.com/seller/subscribe

Thank you for using Burundian Market!
'''
            subject = 'Subscription Ending Soon'
            
        elif notification_type == 'trial_ended':
            message = f'''
Hello {user.username},

Your 5-day trial period has ended.
Your seller account has been deactivated. To reactivate and continue selling, please subscribe.

Visit: https://burundian-market-e8vg.onrender.com/seller/subscribe

Thank you for using Burundian Market!
'''
            subject = 'Trial Period Ended'
            
        elif notification_type == 'subscription_ended':
            message = f'''
Hello {user.username},

Your subscription has ended.
Your seller account has been deactivated. To reactivate and continue selling, please renew your subscription.

Visit: https://burundian-market-e8vg.onrender.com/seller/subscribe

Thank you for using Burundian Market!
'''
            subject = 'Subscription Ended'
        
        # Method 1: Try email (but don't block if it fails)
        try:
            send_notification_email(user.email, subject, message)
            print(f"✅ Email notification sent to {user.email}")
        except Exception as e:
            print(f"❌ Email notification failed for {user.email}: {e}")
        
        # Method 2: Log to console (always works)
        print(f"📢 SUBSCRIPTION NOTIFICATION for {user.username} ({user.email}):")
        print(f"📢 Type: {notification_type}")
        print(f"📢 Status: {status}")
        print(f"📢 Message: {message.strip()}")
        print("---")
        
        # Method 3: Store notification in database for dashboard display (if column exists)
        try:
            if hasattr(user, 'last_notification_sent'):
                user.last_notification_sent = datetime.now()
                db.session.commit()
        except Exception as e:
            print(f"⚠️ Could not update last_notification_sent: {e}")
            
    except Exception as e:
        print(f"❌ Error in notify_subscription_status: {e}")

# Background task to check all seller subscriptions
def check_all_subscriptions():
    """Background task to check all seller subscriptions"""
    with app.app_context():
        try:
            sellers = db.session.query(User).filter_by(user_type='seller').all()
            for seller in sellers:
                try:
                    status = seller.get_subscription_status()
                    
                    # Notify if trial ending in 2 days
                    if status['status'] == 'trial' and status['days_left'] == 2:
                        notify_subscription_status(seller, 'trial_ending')
                    
                    # Notify if subscription ending in 3 days
                    elif status['status'] == 'subscription' and status['days_left'] == 3:
                        notify_subscription_status(seller, 'subscription_ending')
                    
                    # Deactivate if trial ended
                    elif status['status'] == 'trial' and status['days_left'] <= 0 and seller.is_seller_active:
                        seller.is_seller_active = False
                        db.session.commit()
                        notify_subscription_status(seller, 'trial_ended')
                    
                    # Deactivate if subscription ended
                    elif status['status'] == 'subscription' and status['days_left'] <= 0 and seller.is_seller_active:
                        seller.is_seller_active = False
                        db.session.commit()
                        notify_subscription_status(seller, 'subscription_ended')
                        
                except Exception as e:
                    print(f"⚠️ Error processing seller {seller.id}: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error in subscription check: {e}")

# FIXED: Use modern Flask startup method
startup_done = False

@app.before_request
def startup_tasks():
    """Run startup tasks on first request"""
    global startup_done
    if not startup_done:
        check_all_subscriptions()
        startup_done = True

# CRITICAL FIX: Enhanced static file serving for uploaded images
@app.route('/uploads/<path:filename>')
def serve_uploaded_files(filename):
    """Serve uploaded files with proper caching and security"""
    try:
        # Ensure the uploads directory exists
        uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
        if not os.path.exists(uploads_dir):
            os.makedirs(uploads_dir)
            
        response = send_from_directory(uploads_dir, filename)
        # Set proper caching headers - ALLOW CACHING for images
        response.headers['Cache-Control'] = 'public, max-age=3600'  # 1 hour cache
        response.headers['Pragma'] = 'cache'
        return response
    except FileNotFoundError:
        # Return a placeholder image if file not found
        return send_from_directory(os.path.join(app.root_path, 'static'), 'images/placeholder.svg')

# NEW: Function to get absolute image URL with cache busting
def get_image_url(image_path):
    """Get absolute URL for product images with cache busting"""
    if not image_path:
        return url_for('static', filename='images/placeholder.svg') + '?v=1'
    
    # If it's a relative path, serve via our uploads route
    if image_path.startswith('uploads/'):
        filename = image_path.replace('uploads/', '')
        return url_for('serve_uploaded_files', filename=filename) + '?t=' + str(int(time.time()))
    
    return url_for('static', filename=image_path) + '?t=' + str(int(time.time()))

# Routes
@app.route('/')
def home():
    # MODIFIED: Show ALL products regardless of seller status
    products = Product.query.order_by(Product.created_at.desc()).limit(8).all()
    
    # Ensure proper image URLs with cache busting
    for product in products:
        product.image_url = get_image_url(product.image)
    
    return render_template('index.html', products=products)

@app.route('/test-db')
def test_db():
    try:
        users_count = db.session.query(User).count()
        products_count = db.session.query(Product).count()
        
        return jsonify({
            'status': 'success',
            'message': 'Database working without migrations!',
            'users_count': users_count,
            'products_count': products_count
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(e)}'
        }), 500

@app.route('/check-tables')
def check_tables():
    try:
        tables = db.engine.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """).fetchall()
        
        table_list = [table[0] for table in tables]
        return jsonify({
            'tables': table_list,
            'count': len(table_list)
        })
    except Exception as e:
        return f'Error: {e}'

@app.before_request
def refresh_session():
    if 'user_id' in session:
        # Refresh session if it's about to expire
        session.modified = True
        
        # Check if user still exists
        user = db.session.query(User).get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        # Update session with current user data
        session['user_type'] = user.user_type
        session['username'] = user.username

@app.route('/products/search')
def product_search():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 12  # Products per page

    # MODIFIED: Show ALL products regardless of seller status
    products_query = Product.query

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
    
    # Ensure proper image URLs for all products
    for product in products.items:
        product.image_url = get_image_url(product.image)

    return render_template(
        'product_search.html',
        products=products,
        search_query=query,
        categories=categories,
        selected_category=None  # No category selected when doing general search
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()
        remember = 'remember' in request.form  # Check if "remember me" was checked

        if not identifier or not password:
            flash('Please enter both email/username and password', 'danger')
            return redirect(url_for('login'))

        # FIXED QUERY: Use db.session.query() consistently
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

        # Check and notify about subscription status on login
        if user.user_type == 'seller':
            status = user.get_subscription_status()
            if not status['active']:
                if status['status'] == 'trial':
                    notify_subscription_status(user, 'trial_ended')
                    flash('Your trial period has ended. Please subscribe to continue selling.', 'warning')
                else:
                    notify_subscription_status(user, 'subscription_ended')
                    flash('Your subscription has ended. Please renew to continue selling.', 'warning')
            elif status['days_left'] <= 3:
                if status['status'] == 'trial':
                    notify_subscription_status(user, 'trial_ending')
                    flash(f'Your trial ends in {status["days_left"]} days. Please subscribe soon!', 'info')
                else:
                    notify_subscription_status(user, 'subscription_ending')
                    flash(f'Your subscription ends in {status["days_left"]} days. Please renew soon!', 'info')

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form.get('phone')
        user_type = request.form['user_type']
        
        # Only check for username (email check removed) - FIXED QUERY
        existing_user = db.session.query(User).filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create user with auto-verification to avoid email issues
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            phone=phone,
            user_type=user_type,
            email_verified=True,  # Auto-verify to avoid email issues
            is_verified=True      # Auto-verify to avoid email issues
        )
        
        # For sellers, set the trial period
        if user_type == 'seller':
            new_user.is_seller_active = True  # Active during trial
        
        db.session.add(new_user)
        db.session.commit()
        
        # Try to send welcome email (but don't block registration if it fails)
        try:
            token = serializer.dumps(email, salt='email-verification')
            send_verification_email(new_user.email, token)
            flash('Registration successful! Welcome email sent.', 'success')
        except Exception as e:
            # Registration still succeeds even if email fails
            flash('Registration successful! You can now login.', 'success')
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=3600)
    except:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('register'))
    
    user = db.session.query(User).filter_by(email=email).first_or_404()
    
    if user.email_verified:
        flash('Account already verified. Please login.', 'info')
    else:
        user.email_verified = True
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Email verified successfully! You can now login.', 'success')
    
    return redirect(url_for('login'))



@app.before_request
def check_persistent_login():
    if 'user_id' not in session and request.endpoint != 'logout':
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            try:
                user_id = serializer.loads(remember_token, salt='remember-me')
                user = db.session.query(User).get(user_id)
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
        user = db.session.query(User).get(session['user_id'])
        if user:
            user.remember_token = None
            db.session.commit()
    
    session.clear()
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('remember_token')
    response.delete_cookie('session')
    flash('You have been logged out.', 'info')
    return response

@app.route('/seller/dashboard')
def seller_dashboard():
    if 'user_id' not in session or session['user_type'] != 'seller':
        return redirect(url_for('login'))
    
    user = db.session.query(User).get(session['user_id'])
    products = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    
    # Ensure proper image URLs
    for product in products:
        product.image_url = get_image_url(product.image)
    
    # Get subscription status for display
    subscription_status = user.get_subscription_status()
    
    return render_template('seller_dashboard.html', 
                         user=user, 
                         products=products,
                         subscription_status=subscription_status)  # Remove datetime parameter


@app.route('/buyer/dashboard')
def buyer_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    categories = db.session.query(Product.category.distinct()).filter(Product.category.isnot(None)).all()
    categories = [c[0] for c in categories if c[0]]
    
    # MODIFIED: Show ALL products regardless of seller status
    products = Product.query.order_by(Product.created_at.desc()).all()
    
    # Ensure proper image URLs
    for product in products:
        product.image_url = get_image_url(product.image)
    
    return render_template('buyer_dashboard.html', products=products, categories=categories)

@app.route('/product/add', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session or session['user_type'] != 'seller':
        return redirect(url_for('login'))
    
    user = db.session.query(User).get(session['user_id'])
    
    # Check if seller is active
    if not user.is_seller_active:
        flash('Your seller account is not active. Please subscribe to add products.', 'warning')
        return redirect(url_for('seller_subscribe'))
    
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
            filename = f"product_{session['user_id']}_{int(time.time())}.jpg"
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
    product = db.session.query(Product).get_or_404(product_id)
    seller = db.session.query(User).get(product.seller_id)
    
    # Ensure proper image URL with cache busting
    product.image_url = get_image_url(product.image)
    
    # Check if the current user is the seller
    is_seller = 'user_id' in session and session['user_id'] == product.seller_id
    
    # MODIFIED: Show similar products regardless of seller status
    similar_products = Product.query.filter(
        Product.category == product.category,
        Product.id != product.id
    ).limit(4).all()
    
    # Ensure proper image URLs for similar products
    for similar in similar_products:
        similar.image_url = get_image_url(similar.image)
    
    return render_template('product_detail.html', 
                         product=product, 
                         seller=seller, 
                         is_seller=is_seller,
                         similar_products=similar_products)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = db.session.query(User).filter_by(email=email).first()
        
        if user:
            token = serializer.dumps(email, salt='password-reset')
            
            # Try to send email, but show user instructions if it fails
            try:
                send_password_reset_email(user.email, token)
                flash('Password reset link has been sent to your email.', 'info')
            except Exception as e:
                # Email failed, show manual instructions
                reset_url = url_for('reset_password', token=token, _external=True)
                flash(f'Email service temporarily unavailable. Please use this link to reset your password: {reset_url}', 'warning')
                return render_template('reset_link_display.html', reset_url=reset_url)
        else:
            # Always show the same message for security
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
    
    user = db.session.query(User).filter_by(email=email).first()
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

@app.route('/admin/manual-reset', methods=['GET', 'POST'])
def admin_manual_reset():
    """Manual password reset for when email is down"""
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
        
    if request.method == 'POST':
        email = request.form['email']
        user = db.session.query(User).filter_by(email=email).first()
        
        if user:
            # Generate a simple reset token (valid for 1 hour)
            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            flash(f'Manual reset link for {email}: {reset_url}', 'info')
            return render_template('manual_reset_result.html', reset_url=reset_url, email=email)
        else:
            flash('User not found', 'danger')
    
    return render_template('manual_reset.html')

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.query(User).get(session['user_id'])
    
    if request.method == 'POST':
        # Check if username is already taken by another user
        new_username = request.form.get('username')
        if new_username != user.username and db.session.query(User).filter_by(username=new_username).first():
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
    
    user = db.session.query(User).get(session['user_id'])
    
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
    
    product = db.session.query(Product).get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)  # Forbidden for other sellers
    
    user = db.session.query(User).get(session['user_id'])
    if not user.is_seller_active:
        flash('Your seller account is not active. Please subscribe to edit products.', 'warning')
        return redirect(url_for('seller_subscribe'))
    
    if request.method == 'POST':
        product.title = request.form['title']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.category = request.form.get('category')
        
        # Handle image update
        image = request.files.get('image')
        if image and image.filename != '':
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            filename = f"product_{session['user_id']}_{product_id}_{int(time.time())}.jpg"
            image_path = os.path.join(upload_folder, filename)
            image.save(image_path)
            product.image = f"uploads/{filename}"
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('seller_dashboard'))
    
    # Ensure proper image URL for editing
    product.image_url = get_image_url(product.image)
    
    return render_template('edit_product.html', product=product)

@app.route('/product/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        abort(403)  # Forbidden for buyers
    
    product = db.session.query(Product).get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)  # Forbidden for other sellers
    
    # Delete product image if exists
    if product.image:
        try:
            image_path = os.path.join(app.root_path, 'static', product.image)
            if os.path.exists(image_path):
                os.remove(image_path)
        except:
            pass
    
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully', 'success')
    return redirect(url_for('seller_dashboard'))

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    # Get all users with their subscription status
    users = db.session.query(User).order_by(User.created_at.desc()).all()
    
    # Process sellers' subscription status
    ending_soon = []
    for user in users:
        if user.user_type == 'seller':
            status = user.get_subscription_status()
            # Store the status in the user object for template access
            user.subscription_status = status
            if 0 < status['days_left'] <= 5:
                ending_soon.append(user)
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         ending_soon=ending_soon,
                         datetime=datetime)

@app.route('/admin/user/<int:user_id>')
def admin_view_user(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    user = db.session.query(User).get_or_404(user_id)
    products = []
    images = []
    
    if user.user_type == 'seller':
        products = Product.query.filter_by(seller_id=user.id).all()
        # Get all images from products with proper URLs
        images = [get_image_url(product.image) for product in products if product.image]
        
        # Ensure proper image URLs for products
        for product in products:
            product.image_url = get_image_url(product.image)
        
        # Calculate subscription status
        user.subscription_status = user.get_subscription_status()
    
    return render_template('admin_user_detail.html', 
                         user=user, 
                         products=products,
                         images=images,
                         datetime=datetime)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        abort(403)
    
    user = db.session.query(User).get_or_404(user_id)
    username = user.username
    
    try:
        # Delete user's products if they're a seller
        if user.user_type == 'seller':
            # First delete product images
            for product in user.products:
                if product.image:
                    try:
                        image_path = os.path.join(app.root_path, 'static', product.image)
                        if os.path.exists(image_path):
                            os.remove(image_path)
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
    
    seller = db.session.query(User).get_or_404(user_id)
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
        
        # Send notification email asynchronously
        try:
            body = f'''Hello {seller.username},
            
Your subscription has been activated for {days} days (until {seller.subscription_end.strftime('%B %d, %Y')}).
You can now publish your products on Burundian Market.

Thank you for using our service!
'''
            send_notification_email(seller.email, 'Your Subscription Has Been Activated', body)
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
    
    user = db.session.query(User).get_or_404(user_id)
    
    if request.method == 'POST':
        subject = request.form.get('subject', 'Message from Burundian Market Admin')
        message = request.form.get('message', '').strip()
        
        if not message:
            flash('Message cannot be empty', 'danger')
            return redirect(url_for('admin_send_message', user_id=user_id))
        
        try:
            # Send email asynchronously
            send_notification_email(user.email, subject, message)
            
            flash('Message sent successfully!', 'success')
            return redirect(url_for('admin_view_user', user_id=user_id))
        except Exception as e:
            print(f"Error sending message to {user.email}: {str(e)}")
            flash('Failed to send message. Please try again.', 'danger')
    
    return render_template('admin_send_message.html', user=user)

# Seller Subscription Page
@app.route('/seller/subscribe')
def seller_subscribe():
    if 'user_id' not in session or session.get('user_type') != 'seller':
        return redirect(url_for('login'))
    
    user = db.session.query(User).get(session['user_id'])
    subscription_status = user.get_subscription_status()
    return render_template('seller_subscribe.html', user=user, subscription_status=subscription_status)

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
        user = db.session.query(User).get(session['user_id'])
        
        # Check if user exists
        if user is None:
            session.clear()  # Clear invalid session
            flash('User not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        status = user.get_subscription_status()
        
        # If seller's trial period is over (5 days)
        if user.is_seller_active and user.subscription_end is None:
            trial_end = user.created_at + timedelta(days=5)
            if datetime.now() > trial_end:
                user.is_seller_active = False
                db.session.commit()

                # Notify seller with multiple methods
                notify_subscription_status(user, 'trial_ended')
        
        # If subscription is ending in 3 days
        elif user.is_seller_active and user.subscription_end:
            days_left = (user.subscription_end - datetime.now()).days
            if days_left == 3:
                notify_subscription_status(user, 'subscription_ending')
        
        # If subscription has ended
        elif not user.is_seller_active and user.subscription_end and user.subscription_end < datetime.now():
            notify_subscription_status(user, 'subscription_ended')
        
        # Redirect to subscription page if not active
        if not user.is_seller_active and request.endpoint not in ['seller_subscribe', 'choose_subscription', 'logout', 'static', 'edit_profile']:
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
            expires=datetime.now() + timedelta(days=365),
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

# FIXED: Keepalive endpoint without CSRF protection
@app.route('/keepalive', methods=['POST'])
@csrf.exempt  # Exempt from CSRF protection
def keepalive():
    """Enhanced keepalive endpoint that handles session refresh properly"""
    try:
        if 'user_id' in session:
            user = db.session.query(User).get(session['user_id'])
            if user:
                user.last_activity = datetime.utcnow()
                db.session.commit()
                # Refresh the session to extend its lifetime
                session.modified = True
                return jsonify({'status': 'active', 'user_id': user.id}), 200
        return jsonify({'status': 'inactive'}), 200
    except Exception as e:
        print(f"Keepalive error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/checksession')
def check_session():
    if 'user_id' in session:
        user = db.session.query(User).get(session['user_id'])
        if user and (datetime.utcnow() - user.last_activity).total_seconds() < 3600:  # 1 hour
            return {'status': 'active'}, 200
    return {'status': 'expired'}, 401

@app.route('/terms')
def terms():
    return render_template('terms.html', now=datetime.now())

# NEW: Debug route to check image paths
@app.route('/debug-images')
def debug_images():
    """Debug route to check image paths"""
    products = Product.query.limit(5).all()
    debug_info = []
    
    for product in products:
        debug_info.append({
            'id': product.id,
            'title': product.title,
            'image_path': product.image,
            'static_url': url_for('static', filename=product.image) if product.image else None,
            'uploads_url': url_for('serve_uploaded_files', filename=product.image.replace('uploads/', '')) if product.image and product.image.startswith('uploads/') else None,
            'file_exists': os.path.exists(os.path.join(app.root_path, 'static', product.image)) if product.image else False
        })
    
    return jsonify(debug_info)

if __name__ == '__main__':
    app.run(debug=True)