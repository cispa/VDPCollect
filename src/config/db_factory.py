from pathlib import Path
import sqlalchemy as db
from sqlalchemy.orm import declarative_base, sessionmaker

def get_db_components(db_filename: str):
    """Erzeugt SQLAlchemy-Komponenten für eine bestimmte .sqlite-Datei im /data-Verzeichnis"""
    base_dir = Path(__file__).resolve().parents[2]
    print(base_dir)
    db_path = base_dir / 'data' / db_filename

    engine = db.create_engine(f'sqlite:///{db_path}')
    Base = declarative_base()
    DBSession = sessionmaker(bind=engine)

    return engine, Base, DBSession