import sqlalchemy as db

from config.db_factory import get_db_components

engine, Base, DBSession = get_db_components("BugBountyData.sqlite")


class Program(Base):
    __tablename__ = 'programs'
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String)

    programId = db.Column(db.String())
    handle = db.Column(db.String(), nullable=True)
    programURL = db.Column(db.String())
    companyName = db.Column(db.String())
    companyHandle = db.Column(db.String())
    state = db.Column(db.String())
    participation = db.Column(db.String())
    numberJoined = db.Column(db.Integer())
    bugCountValid = db.Column(db.Integer())
    bugCountOverall = db.Column(db.Integer())
    currency = db.Column(db.String())
    maxReward = db.Column(db.Float())
    minReward = db.Column(db.Float())
    bonusReward = db.Column(db.Float())
    safeHarborStatus = db.Column(db.String())
    managed = db.Column(db.Boolean())
    launchedAt = db.Column(db.String())
    stoppedAt = db.Column(db.String())
    baseReward = db.Column(db.Integer())
    avgUpperReward = db.Column(db.Integer())
    avgLowerReward = db.Column(db.Integer())
    triageActive = db.Column(db.String())

    # TODO: change to Json field and postgres
    data = db.Column(db.Text())
    # reports = relationship("Report", back_populates="program")


class Report(Base):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String())

    reportId = db.Column(db.String(), unique=True, nullable=True)
    databaseId = db.Column(db.String())
    activityId = db.Column(db.String())
    programHandle = db.Column(db.String())
    companyHandle = db.Column(db.String())
    programId = db.Column(db.Integer(), nullable=True)
    researcherUsername = db.Column(db.String())
    researcherId = db.Column(db.String())
    researcherProfilePath = db.Column(db.String())
    severity = db.Column(db.String())
    disclosed = db.Column(db.String())
    bounty = db.Column(db.Float())
    currency = db.Column(db.String())
    substate = db.Column(db.String())
    desc = db.Column(db.String())
    createdAt = db.Column(db.String())
    acceptedAt = db.Column(db.String())
    claimedAt = db.Column(db.String())
    closedAt = db.Column(db.String())
    # user = relationship("User", back_populates="reports")
    # program = relationship("Program", back_populates="reports")

    # TODO: change to Json field and postgres
    data = db.Column(db.String())


class User(Base):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String())

    uuid = db.Column(db.String())
    name = db.Column(db.String())
    path = db.Column(db.String())
    rank = db.Column(db.String())
    accuracy = db.Column(db.Float())
    numValidReports = db.Column(db.Integer())
    overallReports = db.Column(db.Integer())
    avgSeverity = db.Column(db.Float())
    country = db.Column(db.String())
    createdAt = db.Column(db.String())
    twitter = db.Column(db.String())
    linkedin = db.Column(db.String())
    github = db.Column(db.String())
    gitlab = db.Column(db.String())
    htb = db.Column(db.String())
    bugcrowd = db.Column(db.String())
    website = db.Column(db.String())

    # TODO: change to Json field and postgres
    data = db.Column(db.String())


class Scope(Base):
    __tablename__ = 'scopes'
    id = db.Column(db.Integer, primary_key=True)
    originId = db.Column(db.String())
    source = db.Column(db.String())
    programHandle = db.Column(db.String())
    companyHandle = db.Column(db.String())
    #  None = initial
    #  New = newly added
    #  Removed = was removed
    #  Reintroduced = deleted and activated again
    type = db.Column(db.String())
    inScope = db.Column(db.Boolean())
    bounties = db.Column(db.Boolean())
    scope = db.Column(db.String())
    bountyIdentifier = db.Column(db.String())
    maxSeverity = db.Column(db.String())
    desc = db.Column(db.String())
    tags = db.Column(db.String())
    date = db.Column(db.String())
    data = db.Column(db.String())
    vpnNeeded=db.Column(db.Boolean())
    headerExtension=db.Column(db.String())


class Bounty(Base):
    __tablename__ = "bounties"
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String())
    originId = db.Column(db.String())
    bountyRowId = db.Column(db.Integer())
    programHandle = db.Column(db.String())
    companyHandle = db.Column(db.String())
    bountyIdentifier = db.Column(db.String())
    bounty = db.Column(db.String())
    currency = db.Column(db.String())
    #  None = initial
    #  Changed = Changed bounty amount
    type = db.Column(db.String())
    date = db.Column(db.String())
    # kinda useless
    data = db.Column(db.String())


class Rule(Base):
    __tablename__ = "rules"
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String())
    programHandle = db.Column(db.String())
    companyHandle = db.Column(db.String())
    companyName = db.Column(db.String())
    rules = db.Column(db.String())
    date = db.Column(db.String())


class VulnerabilityTypes(Base):
    __tablename__ = "vulnerabilityTypes"
    id = db.Column(db.Integer(), primary_key=True)
    source = db.Column(db.String())
    inScope = db.Column(db.Boolean())
    programHandle = db.Column(db.String())
    companyHandle = db.Column(db.String())
    vulnTypes = db.Column(db.String())
    date = db.Column(db.String())


class Backup(Base):
    __tablename__ = "backups"
    id = db.Column(db.Integer(), primary_key=True)
    source = db.Column(db.String())
    type = db.Column(db.String())
    identifier = db.Column(db.String())
    date = db.Column(db.String())
    data = db.Column(db.String())


Base.metadata.create_all(engine)
session = DBSession()
session.commit()
session.close()
