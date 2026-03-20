import re
import time
import uuid
from datetime import datetime
from typing import Annotated, Optional, Any
from typing_extensions import Self

from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response
import hashlib
import hmac
from pydantic import BaseModel, EmailStr, field_validator
from starlette.responses import JSONResponse

SECRET_KEY = "super-secret-key-change-in-production"
SESSION_LIFETIME = 300   # 5 минут
RENEW_THRESHOLD = 180

simple_sessions: dict[str, str] = {}

ACCEPT_LANGUAGE_RE = re.compile(
    r"^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})?"
    r"(,\s*[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})?(;q=[01](\.\d{1,3})?)?)*$"
)

#3.1
app = FastAPI(title='tasr 3.1 - user creation')


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = None
    is_subscribed: Optional[bool] = None

    @field_validator('age')
    @classmethod
    def age_must_be_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError('age must be a positive integer')
        return v


@app.post("/creare_user")
def create_user(user: UserCreate):
    return user
#3.2
app = FastAPI(title="Task 3.2 - Products")

sample_products = [
    {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99},
    {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99},
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99},
]
@app.get('/products/search')
def search_products(
        keyword: str,
        category: Optional[str] = None,
        limit: int = 10,
):
    results = [p for p in sample_products if keyword.lower()in p ['name'].lower()
               and (category is None or p['category'].lower() == category.lower())]
    return results[:limit]


@app.get("/product/{product_id}")
def get_product(product_id: int):
    for p in sample_products:
        if p["product_id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")
#5.1
app = FastAPI(titile='task 5.1 - cookie auth')

users = {'user123': 'password123',
         'admin': 'admin',
         }

sessions: dict[str, str] = {}


class LoginData(BaseModel):
    username: str
    password: str


@app.post('/login')
def login(data: LoginData, responce: Response):
    if users.get(data.username) != data.password:
        responce.status_code = 401
        return {'message': 'invalid credentials'}

    token = str(uuid.uuid4())
    sessions[token] = data.username

    responce.set_cookie(
        key='session_token',
        value=token,
        httponly=True,
        max_age=3600
    )
    return {'message': 'logged in successfully'}


@app.get('/user')
def get_user(responce: Response, session_token: Optional[str] = Cookie(default=None)):
    if session_token is None or session_token not in sessions:
        responce.status_code = 401
        return {'message': 'unauthorized'}

    username = sessions[session_token]
    return {
        'username': username,
        'email': f'{username}@example.com',
        'role': 'admin' if username == 'admin' else 'user',
    }
#5.2
def _sign(value: str) -> str:
    """Возвращает HMAC-SHA256 подпись для строки value."""
    return hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def _make_signed_token(user_id: str) -> str:
    return f"{user_id}.{_sign(user_id)}"


def _verify_signed_token(token: str) -> Optional[str]:
    """Возвращает user_id если подпись верна, иначе None."""
    try:
        user_id, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    if hmac.compare_digest(_sign(user_id), sig):
        return user_id
    return None


@app.post("/login/signed", tags=["5.2 — Подписанная cookie"])
def login_signed(data: LoginData, response: Response):
    """Логин с подписанным токеном (hmac)."""
    user = users.get(data.username)
    if user is None or user["password"] != data.password:
        response.status_code = 401
        return {"message": "Invalid credentials"}

    user_id = str(uuid.uuid4())
    token = _make_signed_token(user_id)  # "<user_id>.<signature>"
    response.set_cookie(key="signed_token", value=token, httponly=True, max_age=3600)
    return {"message": "Logged in", "user_id": user_id}


@app.get("/profile", tags=["5.2 — Подписанная cookie"])
def profile(response: Response, signed_token: Optional[str] = Cookie(default=None)):
    """Проверяет подпись cookie и возвращает user_id."""
    if signed_token is None:
        response.status_code = 401
        return {"message": "Unauthorized"}
    user_id = _verify_signed_token(signed_token)
    if user_id is None:
        response.status_code = 401
        return {"message": "Unauthorized"}
    return {"user_id": user_id, "message": "Valid signed session"}
#5.3
def _make_sliding_token(user_id: str, ts: float) -> str:
    payload = f"{user_id}.{int(ts)}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _parse_sliding_token(token: str) -> tuple[str, int]:
    """Возвращает (user_id, timestamp) или выбрасывает ValueError при подделке."""
    try:
        user_id, ts_str, sig = token.rsplit(".", 2)
    except ValueError:
        raise ValueError("bad token format")
    payload = f"{user_id}.{ts_str}"
    expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("invalid signature")
    return user_id, int(ts_str)


def _set_sliding_cookie(response: Response, user_id: str, ts: float):
    response.set_cookie(
        key="sliding_token",
        value=_make_sliding_token(user_id, ts),
        httponly=True,
        secure=False,  # в продакшене True
        max_age=SESSION_LIFETIME,
    )


@app.post("/login/sliding", tags=["5.3 — Скользящая сессия"])
def login_sliding(data: LoginData, response: Response):
    """Логин со скользящей сессией."""
    user = users.get(data.username)
    if user is None or user["password"] != data.password:
        response.status_code = 401
        return {"message": "Invalid credentials"}

    user_id = str(uuid.uuid4())
    _set_sliding_cookie(response, user_id, time.time())
    return {"message": "Logged in", "user_id": user_id}


@app.get("/profile/sliding", tags=["5.3 — Скользящая сессия"])
def profile_sliding(
        response: Response,
        sliding_token: Optional[str] = Cookie(default=None),
):
    """
    Скользящая сессия:
      elapsed < 3 мин          → не продлевать
      3 мин ≤ elapsed < 5 мин  → продлить куку
      elapsed ≥ 5 мин          → 401 Session expired
      подделка данных           → 401 Invalid session
    """
    if sliding_token is None:
        response.status_code = 401
        return {"message": "Unauthorized"}

    try:
        user_id, last_active = _parse_sliding_token(sliding_token)
    except ValueError:
        response.status_code = 401
        return {"message": "Invalid session"}

    elapsed = time.time() - last_active

    if elapsed >= SESSION_LIFETIME:
        response.status_code = 401
        return {"message": "Session expired"}

    renewed = False
    if RENEW_THRESHOLD <= elapsed < SESSION_LIFETIME:
        _set_sliding_cookie(response, user_id, time.time())
        renewed = True

    return {
        "user_id": user_id,
        "elapsed_seconds": round(elapsed, 1),
        "session_renewed": renewed,
    }
#5.4
@app.get('/headers', tags=['5.4 - заголовки'])
def get_headers(request: Request):
    user_agent = request.headers.get('user-agent')
    accept_language = request.headers.get('accept-language')
    if not user_agent:
        raise HTTPException(status_code=400, detail='missing required header: accept-language')
    if not ACCEPT_LANGUAGE_RE.match(accept_language):
        raise HTTPException(
            status_code=400,
            detail="Invalid Accept-Language format. Expected e.g. 'en-US,en;q=0.9,es;q=0.8'",
        )

    return {"User-Agent": user_agent, "Accept-Language": accept_language}
#5.5

class CommonHeaders(BaseModel):
    user_agent: str
    accept_language: str

    @field_validator('accept_language')
    @classmethod
    def validate_accept_language(cls, v: str) -> str:
        if not ACCEPT_LANGUAGE_RE.match(v):
            raise ValueError(
                "invalid accept-language format, expected e.g. 'en_US,en:q=0.9,es;q=0.8'"
            )
        return v
    model_config = {'populate_by_name': True}


@app.get('/headers/model', tags='5.5 - CommonHeaders')
def headers_model(headers: Annotated[CommonHeaders, Header()]):
    return {
        'user-agent': headers.user_agent,
        'accept_language': headers.accept_language,
    }


@app.get('/info', tags=['5.5 - CommonHeaders'])
def info_route(headers: Annotated[CommonHeaders, Header()]):
    body = {"message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent":      headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }
    resp = JSONResponse(content=body)
    resp.headers["X-Server-Time"] = datetime.now().isoformat(timespec="seconds")
    return resp