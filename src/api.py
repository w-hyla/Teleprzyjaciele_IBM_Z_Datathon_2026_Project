import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

# Ensure repository root is on sys.path so `src` can be imported as a package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import create_pipeline

app = FastAPI()

class Transaction(BaseModel):
    step: int = None
    type: str = None
    amount: float = 0.0
    nameOrig: str = None
    oldbalanceOrg: float = 0.0
    newbalanceOrig: float = 0.0
    nameDest: str = None
    oldbalanceDest: float = 0.0
    newbalanceDest: float = 0.0

class APIInuput(BaseModel):
    transaction: Transaction
    domain: str = None

pipeline = create_pipeline()

@app.post("/check")
async def post(item: APIInuput):
    return await pipeline.process_transaction(item.model_dump())


if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=True)