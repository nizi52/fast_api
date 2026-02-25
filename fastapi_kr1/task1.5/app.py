from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class User(BaseModel):
    name: str
    age: int


class UserResponse(BaseModel):
    name: str
    age: int
    is_adult: bool


@app.post("/user", response_model=UserResponse)
def create_user(user: User):
    is_adult = user.age >= 18
    return UserResponse(name=user.name, age=user.age, is_adult=is_adult)



