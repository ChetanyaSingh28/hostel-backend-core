import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

try:
    print("Connecting to DB...")
    db = pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", "")
    )
    cursor = db.cursor()
    print("Dropping existing database...")
    cursor.execute('DROP DATABASE IF EXISTS hostel_system')
    print("Creating new database...")
    cursor.execute('CREATE DATABASE hostel_system')
    cursor.execute('USE hostel_system')
    print("Reading schema...")
    with open('../database/schema.sql', 'r', encoding='utf-8') as f:
        schema = f.read()
    
    # Split by semicolon and run each
    statements = [s.strip() for s in schema.split(';') if s.strip()]
    for s in statements:
        cursor.execute(s)

    db.commit()
    print("Successfully rebuilt DB!")
except Exception as e:
    print("Error:", e)
