import re
from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

app = FastAPI()

feedbacks = []

BANNED_WORDS_PATTERN = re.compile(
    r"\b(кринж\w*|рофл\w*|вайб\w*)\b",
    re.IGNORECASE
)


class Feedback(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    message: str = Field(min_length=10, max_length=500)

    @field_validator("message")
    @classmethod
    def check_banned_words(cls, v: str) -> str:
        if BANNED_WORDS_PATTERN.search(v):
            raise ValueError("Использование недопустимых слов")
        return v


@app.post("/feedback")
def submit_feedback(feedback: Feedback):
    feedbacks.append(feedback)
    return {"message": f"Спасибо, {feedback.name}! Ваш отзыв сохранён."}

