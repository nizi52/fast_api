from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

feedbacks = []


class Feedback(BaseModel):
    name: str
    message: str


@app.post("/feedback")
def submit_feedback(feedback: Feedback):
    feedbacks.append(feedback)
    return {"message": f"Feedback received. Thank you, {feedback.name}."}

