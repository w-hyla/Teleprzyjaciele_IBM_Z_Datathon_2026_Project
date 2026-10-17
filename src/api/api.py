import uvicorn
from fastapi import FastAPI
from domain_analyzer import analyze
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]   # /work/src/api/api.py -> /work
csv_path = PROJECT_ROOT / "data" / "tranco_top.csv"

trusted = pd.read_csv(csv_path, header=None, usecols=[1])[1].tolist()

app = FastAPI()

@app.get("/{item_id}")
def read(item_id: str):
    return analyze(item_id, trusted)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=True)