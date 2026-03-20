from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Numbers(BaseModel):
    num1: float
    num2: float

@app.post("/calculate")
def calculate(numbers: Numbers):
    result = numbers.num1 + numbers.num2
    return {"result": result}

# Пример запроса:
# curl -X POST "http://localhost:8000/calculate" \
#      -H "Content-Type: application/json" \
#      -d '{"num1": 5, "num2": 10}'
