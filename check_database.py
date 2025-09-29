# check_database.py
from app import app, db

with app.app_context():
    try:
        # Check if alembic_version table exists and what's in it
        result = db.engine.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """).fetchall()
        
        print("📊 Tables in database:")
        for table in result:
            print(f"   - {table[0]}")
            
        # Check alembic_version specifically
        try:
            version = db.engine.execute("SELECT version_num FROM alembic_version").scalar()
            print(f"🔍 Current alembic version: {version}")
        except:
            print("🔍 No alembic_version table found")
            
    except Exception as e:
        print(f"❌ Error: {e}")