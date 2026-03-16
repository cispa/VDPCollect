from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String
import psycopg2
import os
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[5]
print(str(BASE_DIR))
load_dotenv(BASE_DIR / ".env")

DB_USER = os.environ.get("DB_USER_PG")
DB_PASS = os.environ.get("DB_PASS_PG")
DB_HOST = os.environ.get("DB_HOST_PG", "localhost")
DB_PORT = os.environ.get("DB_PORT_PG", "5432")
DB_NAME = os.environ.get("DB_NAME_PG")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# ---------- STEP 1: ensure database exists ----------
conn = psycopg2.connect(
    dbname="postgres",
    user=DB_USER,
    password=DB_PASS,
    host=DB_HOST,
    port=DB_PORT
)

conn.autocommit = True
cur = conn.cursor()

cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (DB_NAME,))
exists = cur.fetchone()

if not exists:
    print("[+] Creating database...")
    cur.execute(f'CREATE DATABASE "{DB_NAME}"')
else:
    print("[+] Database already exists")

cur.close()
conn.close()

# ---------- STEP 2: create tables ----------
Base = declarative_base()

class Taint(Base):
    __tablename__ = 'taints'
    id = Column(String(32), primary_key=True, unique=True)
    url = Column(String, nullable=False)
    taint = Column(String, nullable=False)
    source = Column(String, nullable=False)
    sink = Column(String, nullable=False)
    finding = Column(String, nullable=False)

engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)

print("[+] Tables created/verified")