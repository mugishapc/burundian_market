from app import app, db, Product, User
from werkzeug.security import generate_password_hash

with app.app_context():
    db.drop_all()  # optional: removes all existing tables
    db.create_all()  # creates all tables for known models

    # Add a default admin if not exists
    if not User.query.filter_by(email='mugishapc1@gmail.com').first():
        admin = User(
            username='TEAM MANAGEMENT',
            email='mugishapc1@gmail.com',
            password=generate_password_hash('61Mpc588214#'),
            user_type='admin',
            is_verified=True,
            email_verified=True
        )
        db.session.add(admin)
        db.session.commit()

print("✅ Database initialized successfully.")
