import json
import hashlib
import logging
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

# Enable logging
logging.basicConfig(level=logging.DEBUG)
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for flexibility
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TaintFlow(BaseModel):
    url: str
    details: Dict[str, Any]
    taintFlows: List[Any]
    source: str
    sink: str
    finding: Dict[str, Any]

# For storeing the data
Base = declarative_base()
class Taint(Base):
    __tablename__ = 'taints'
    id = Column(String(32), primary_key=True, unique=True)  
    url = Column(String, nullable=False)
    taint = Column(String, nullable=False)  
    source = Column(String, nullable=False)  
    sink = Column(String, nullable=False)   
    finding = Column(String, nullable=False)

# Store taint data in the database
def storeTaintInDB(session, data):
    logging.debug("Attempting to store taint data in the database...")
    json_str = json.dumps(data, sort_keys=True)
    json_bytes = json_str.encode('utf-8')
    md5hash = hashlib.md5(json_bytes).hexdigest()

    new_taint = Taint(
        id=md5hash,
        url=data['url'],
        taint=json.dumps(data['taintFlows']),
        source=data['source'],
        sink=data['sink'],
        finding=json.dumps(data['finding'])
    )
    
    try:
        session.add(new_taint)
        session.commit()
        logging.debug("Taint stored successfully.")
    except IntegrityError:
        session.rollback()
        logging.warning("Duplicate entry (hash): This taint already exists.")


# Create necessarily sessions
DATABASE_URL = f"postgresql://{os.environ['DB_USER_PG']}:{os.environ['DB_PASS_PG']}@{os.environ['DB_HOST_PG']}:{os.environ['DB_PORT_PG']}/{os.environ['DB_NAME_PG']}"
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True
)
Session = sessionmaker(bind=engine)

# FastAPI endpoint used to receive the data
@app.post("/taintreport")
async def receive_taint_data(taintDataBatch: List[TaintFlow]):
    session = None
    try:
        session = Session()  # Open session before processing
        
        # Loop through each taint object in the batch
        for taintObject in taintDataBatch:
            taint_object_dict = taintObject.dict()
            storeTaintInDB(session, taint_object_dict)
        
        session.commit()  # Commit the changes after processing the entire batch
        logging.info(f"Successfully stored {len(taintDataBatch)} taint report entries.")
        return {"status": "success", "message": f"Received {len(taintDataBatch)} taint report entries"}

    except Exception as e:
        if session:
            session.rollback()  # Rollback if any exception occurs
        logging.error(f"Error processing taint data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if session:
            session.close()  # Close session in the finally block
