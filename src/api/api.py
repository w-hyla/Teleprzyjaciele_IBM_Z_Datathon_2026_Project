import uvicorn
from fastapi import FastAPI

import domain_analyzer

app = FastAPI()

@app.get("/{item_id}")
def read(item_id: str):
    return domain_analyzer.analyze(item_id)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=True)