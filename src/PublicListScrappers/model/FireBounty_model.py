import sqlalchemy as db

from config.db_factory import get_db_components


engine, Base, DBSession = get_db_components("FireBountyData.sqlite")


class Program(Base):
    __tablename__ = 'programs'
    key = db.Column(db.String(), primary_key=True)
    handle = db.Column(db.String())
    tag = db.Column(db.String())
    type=db.Column(db.String())
    programURL = db.Column(db.String())


class Scope(Base):
    __tablename__ = 'scopes'
    key = db.Column(db.String(), primary_key=True)
    programHandle = db.Column(db.String())
    type=db.Column(db.String())
    inScope = db.Column(db.Boolean())
    scope = db.Column(db.String())

Base.metadata.create_all(engine)
session = DBSession()
session.commit()
session.close()