import sqlalchemy as db

from config.db_factory import get_db_components

engine, Base, DBSession = get_db_components("CollectedData.sqlite")


class Urls(Base):
    __tablename__ = 'urls'
    identifier = db.Column(db.String, primary_key=True)
    
    # basic information to track origin
    url= db.Column(db.String)
    handle= db.Column(db.String)
    source = db.Column(db.String)
    provider = db.Column(db.String)

    # added a URL entry to store the URL we end up on -> for checking redirects to same page in analysis later
    final_url = db.Column(db.String)

    # To enrich the urls with subpaths
    base= db.Column(db.Boolean)
    base_url= db.Column(db.String)

    # Headers as list
    headers= db.Column(db.String)

    # CSP Evaluation as json
    csp_rating = db.Column(db.String)

    # Cookies as json
    cookies = db.Column(db.String)

    # Included Scripts as list
    included_scripts = db.Column(db.String)

    # retire.js
    retirejs = db.Column(db.String)

    # Certificate data - sslscan as xml or json
    sslscan = db.Column(db.String) 

    # Lighthouse Scan Results as json
    lighthouse = db.Column(db.String)

    # XSS data - json
    xss_data = db.Column(db.String)

    # Prototype Pollution
    proto_data = db.Column(db.String)


Base.metadata.create_all(engine)
session = DBSession()
session.commit()
session.close()
