import uvicorn
from fastapi import FastAPI

from domain_analyzer import analyze

app = FastAPI()

@app.get("/{item_id}")
def read(item_id: str):
    return analyze(item_id)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=True)