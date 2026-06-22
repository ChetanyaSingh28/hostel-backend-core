import os
import pymysql
from dotenv import load_dotenv
from flask import g
from urllib.parse import urlparse

load_dotenv()

def get_db():
    if 'db' not in g:
        database_url = os.getenv("DATABASE_URL")
        if database_url:
            parsed = urlparse(database_url)
            db_host = parsed.hostname
            db_user = parsed.username
            db_pass = parsed.password
            db_port = parsed.port or 3306
            db_name = parsed.path.lstrip('/')
        else:
            db_host = os.getenv("DB_HOST", "localhost")
            db_user = os.getenv("DB_USER", "root")
            db_pass = os.getenv("DB_PASS", "")
            db_name = os.getenv("DB_NAME", "hostel_system")
            db_port = int(os.getenv("DB_PORT", 3306))

        g.db = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_pass,
            database=db_name,
            port=db_port,
            autocommit=False
        )
    return g.db

def get_cursor():
    if 'cursor' not in g:
        g.cursor = get_db().cursor(pymysql.cursors.DictCursor)
    return g.cursor

class DBProxy:
    def commit(self):
        get_db().commit()
    def rollback(self):
        get_db().rollback()
    def ping(self, reconnect=True):
        try:
            get_db().ping(reconnect=reconnect)
        except Exception:
            pass
    def cursor(self, *args, **kwargs):
        return get_db().cursor(*args, **kwargs)

class CursorProxy:
    def execute(self, query, args=None):
        return get_cursor().execute(query, args)
    def fetchone(self):
        return get_cursor().fetchone()
    def fetchall(self):
        return get_cursor().fetchall()
    def fetchmany(self, size=None):
        if size is None:
            return get_cursor().fetchmany()
        return get_cursor().fetchmany(size)
    def close(self):
        if 'cursor' in g:
            g.cursor.close()
            del g.cursor

db = DBProxy()
cursor = CursorProxy()
