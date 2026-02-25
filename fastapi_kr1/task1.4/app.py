from fastapi import FastAPI
from models import User

app = FastAPI()

user = User(name="Иван Иванов", id=1)


@app.get("/users")
def get_user():
    return user

# Запуск: uvicorn app:app --reload
# Открыть: http://localhost:8000/users
