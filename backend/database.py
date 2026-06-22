"""Connexion à la base de données PostgreSQL (via Railway) avec fallback SQLite en local."""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./rift.db")

# Railway fournit l'URL au format postgres:// ou postgresql://, mais on force le driver
# pg8000 (100% Python) plutôt que psycopg2 pour éviter les soucis de librairie système
# manquante (libpq.so.5) dans certains environnements de build.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+pg8000://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL and "+pg8000" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
