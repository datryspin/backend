from datetime import datetime, timedelta
import os
from typing import Optional, List

import httpx
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlmodel import SQLModel, Field as ORMField, create_engine, Session, select

from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-to-a-random-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./db.sqlite")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


# ---- Models ----
class User(SQLModel, table=True):
    id: Optional[int] = ORMField(default=None, primary_key=True)
    username: str = ORMField(index=True, unique=True)
    hashed_password: str
    cash_usd: float = 10000.0  # starting cash in USD


class Order(SQLModel, table=True):
    id: Optional[int] = ORMField(default=None, primary_key=True)
    user_id: int = ORMField(index=True)
    pair: str  # e.g., "EUR/USD"
    side: str  # "buy" or "sell"
    type: str = "market"  # for now only market
    amount: float  # amount in base currency (e.g., 100 EUR)
    price: Optional[float] = None  # executed price (quote per base)
    filled: bool = False
    created_at: datetime = ORMField(default_factory=datetime.utcnow)


class Position(SQLModel, table=True):
    id: Optional[int] = ORMField(default=None, primary_key=True)
    user_id: int = ORMField(index=True)
    base: str  # e.g., "EUR"
    quote: str  # e.g., "USD"
    amount_base: float = 0.0  # positive for long base, negative for short


# ---- Pydantic Schemas ----
class RegisterIn(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class OrderIn(BaseModel):
    pair: str = Field(..., example="EUR/USD")
    side: str = Field(..., example="buy")
    amount: float = Field(..., example=100.0)  # amount in base currency


class OrderOut(BaseModel):
    id: int
    pair: str
    side: str
    amount: float
    price: Optional[float]
    filled: bool
    created_at: datetime


class PositionOut(BaseModel):
    base: str
    quote: str
    amount_base: float


# ---- Utility / Auth ----
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_username(session: Session, username: str) -> Optional[User]:
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()


def authenticate_user(session: Session, username: str, password: str) -> Optional[User]:
    user = get_user_by_username(session, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    with Session(engine) as session:
        user = get_user_by_username(session, username)
        if user is None:
            raise credentials_exception
        return user


# ---- Market Data ----
# Uses exchangerate.host (no API key)
async def fetch_rate(base: str, quote: str) -> float:
    async with httpx.AsyncClient(timeout=10.0) as client:
        url = f"https://api.exchangerate.host/latest?base={base}&symbols={quote}"
        r = await client.get(url)
        r.raise_for_status()
        data = r.json()
        rate = data["rates"].get(quote)
        if rate is None:
            raise HTTPException(status_code=400, detail="Invalid currency pair")
        return float(rate)


async def fetch_timeseries(base: str, quote: str, start_date: str, end_date: str):
    async with httpx.AsyncClient(timeout=30.0) as client:
        url = f"https://api.exchangerate.host/timeseries?start_date={start_date}&end_date={end_date}&base={base}&symbols={quote}"
        r = await client.get(url)
        r.raise_for_status()
        return r.json()


# ---- Broker (paper) ----
async def execute_market_order(session: Session, user: User, pair: str, side: str, amount_base: float) -> Order:
    base, quote = pair.strip().upper().split("/")
    rate = await fetch_rate(base, quote)  # price = quote per base, e.g., USD per EUR
    # cost in quote currency:
    cost_quote = amount_base * rate
    # For simplicity, account cash is in USD (quote), and we only allow pairs quoted in USD for MVP.
    if quote != "USD":
        # In this MVP we restrict to USD-quoted pairs for simple cash accounting.
        raise HTTPException(status_code=400, detail="MVP supports pairs quoted in USD only (e.g., EUR/USD)")

    if side == "buy":
        if user.cash_usd < cost_quote:
            raise HTTPException(status_code=400, detail="Insufficient USD cash")
        user.cash_usd -= cost_quote
        # update or create position
        statement = select(Position).where(Position.user_id == user.id, Position.base == base, Position.quote == quote)
        pos = session.exec(statement).first()
        if not pos:
            pos = Position(user_id=user.id, base=base, quote=quote, amount_base=amount_base)
            session.add(pos)
        else:
            pos.amount_base += amount_base
    elif side == "sell":
        # ensure position exists and sufficient base to sell
        statement = select(Position).where(Position.user_id == user.id, Position.base == base, Position.quote == quote)
        pos = session.exec(statement).first()
        if not pos or pos.amount_base < amount_base:
            raise HTTPException(status_code=400, detail="Insufficient base currency to sell")
        pos.amount_base -= amount_base
        user.cash_usd += cost_quote
    else:
        raise HTTPException(status_code=400, detail="side must be 'buy' or 'sell'")

    order = Order(user_id=user.id, pair=pair.upper(), side=side, type="market", amount=amount_base, price=rate, filled=True)
    session.add(order)
    session.add(user)
    session.commit()
    session.refresh(order)
    return order


# ---- App & Routes ----
app = FastAPI(title="kiprops-forex (paper trading MVP)")


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.post("/register", status_code=201)
def register(payload: RegisterIn):
    with Session(engine) as session:
        if get_user_by_username(session, payload.username):
            raise HTTPException(status_code=400, detail="Username already registered")
        user = User(username=payload.username, hashed_password=get_password_hash(payload.password))
        session.add(user)
        session.commit()
        session.refresh(user)
        return {"id": user.id, "username": user.username}


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user = authenticate_user(session, form_data.username, form_data.password)
        if not user:
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
        return {"access_token": access_token, "token_type": "bearer"}


@app.get("/market/{pair}")
async def market_rate(pair: str):
    try:
        base, quote = pair.strip().upper().split("/")
    except Exception:
        raise HTTPException(status_code=400, detail="pair must be BASE/QUOTE, e.g. EUR/USD")
    rate = await fetch_rate(base, quote)
    return {"pair": f"{base}/{quote}", "rate": rate, "fetched_at": datetime.utcnow().isoformat()}


@app.get("/history/{pair}")
async def history(pair: str, start: str, end: str):
    try:
        base, quote = pair.strip().upper().split("/")
    except Exception:
        raise HTTPException(status_code=400, detail="pair must be BASE/QUOTE, e.g. EUR/USD")
    data = await fetch_timeseries(base, quote, start, end)
    return data


@app.post("/orders", response_model=OrderOut)
async def place_order(payload: OrderIn, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        # reload user in session
        user = session.get(User, current_user.id)
        # only market orders supported in MVP
        if payload.amount <= 0:
            raise HTTPException(status_code=400, detail="amount must be positive")
        order = await execute_market_order(session, user, payload.pair, payload.side.lower(), payload.amount)
        return OrderOut(
            id=order.id,
            pair=order.pair,
            side=order.side,
            amount=order.amount,
            price=order.price,
            filled=order.filled,
            created_at=order.created_at,
        )


@app.get("/orders", response_model=List[OrderOut])
def list_orders(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        statement = select(Order).where(Order.user_id == current_user.id).order_by(Order.created_at.desc())
        orders = session.exec(statement).all()
        return [
            OrderOut(
                id=o.id,
                pair=o.pair,
                side=o.side,
                amount=o.amount,
                price=o.price,
                filled=o.filled,
                created_at=o.created_at,
            )
            for o in orders
        ]


@app.get("/positions", response_model=List[PositionOut])
def list_positions(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        statement = select(Position).where(Position.user_id == current_user.id)
        positions = session.exec(statement).all()
        return [PositionOut(base=p.base, quote=p.quote, amount_base=p.amount_base) for p in positions]


@app.get("/account")
def account(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        user = session.get(User, current_user.id)
        # compute unrealized P&L for positions quoted in USD
        statement = select(Position).where(Position.user_id == user.id)
        positions = session.exec(statement).all()
    pnl_total = 0.0
    details = []
    for p in positions:
        if p.quote != "USD":
            continue
        # fetch current rate synchronously via httpx (async allowed, but this is fine)
        rate = httpx.get(f"https://api.exchangerate.host/latest?base={p.base}&symbols={p.quote}").json()["rates"][p.quote]
        market_value = p.amount_base * rate
        details.append({"pair": f"{p.base}/{p.quote}", "amount_base": p.amount_base, "market_value_quote": market_value})
        pnl_total += market_value
    return {"username": current_user.username, "cash_usd": current_user.cash_usd, "positions_value_usd": pnl_total, "positions": details}