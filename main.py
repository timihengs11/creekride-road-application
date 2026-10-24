
from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import uuid

SECRET_KEY = "creekride-secret-2025-bayelsa-to-world"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="CreekRide Road API - FIXED V2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# FIX BCRYPT 72 BYTE BUG
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=False)

def get_password_hash(password: str):
    return pwd_context.hash(password[:72] if isinstance(password, str) else password)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain[:72] if isinstance(plain, str) else plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

users_db = {}
rides_db = []
bookings_db = []

# --- PROPER MODELS SO DOCS SHOW FIELDS ---
class RegisterIn(BaseModel):
    full_name: str
    email: str
    password: str

class LoginIn(BaseModel):
    email: str
    password: str

class RideIn(BaseModel):
    origin: str = "Yenagoa"
    destination: str = "Brass"
    date: Optional[str] = None
    price: str = "8000"
    seats: str = "4"

@app.get("/")
def root():
    return {"message": "CreekRide Bayelsa to the World - Backend LIVE 200 OK - FIXED V2", "rides": len(rides_db), "users": len(users_db)}

@app.post("/register")
def register(data: RegisterIn):
    email = data.email.lower().strip()
    if email in users_db:
        raise HTTPException(status_code=400, detail="User already exists - please login")
    hashed = get_password_hash(data.password)
    user_id = str(uuid.uuid4())
    users_db[email] = {"id": user_id, "full_name": data.full_name, "email": email, "password_hash": hashed}
    return {"message": "User registered successfully!", "user_id": user_id, "email": email, "full_name": data.full_name}

@app.post("/login")
def login(data: LoginIn = None, form_data: OAuth2PasswordRequestForm = Depends()):
    email = None
    password = None
    # Try JSON
    if data and data.email:
        email = data.email
        password = data.password
    # Try form
    if form_data and form_data.username:
        # form_data overrides if present
        try:
            if form_data.username and form_data.username != "":
                email = form_data.username
                password = form_data.password
        except:
            pass
    # If data is None because using form, get from form_data
    if not email:
        if form_data:
            email = form_data.username
            password = form_data.password
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    email = email.lower().strip()
    if email not in users_db:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user = users_db[email]
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(data={"sub": email})
    return {"access_token": token, "token_type": "bearer", "email": email, "full_name": user["full_name"]}

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email or email not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        return users_db[email]
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

@app.get("/rides")
def get_rides():
    return rides_db

@app.post("/rides")
def create_ride(data: RideIn, current_user: dict = Depends(get_current_user)):
    ride = {
        "id": str(uuid.uuid4()),
        "origin": data.origin,
        "destination": data.destination,
        "date": data.date or datetime.now().strftime("%Y-%m-%d"),
        "price": data.price,
        "seats": data.seats,
        "driver": current_user["email"],
        "driver_name": current_user["full_name"],
        "created_at": datetime.now().isoformat()
    }
    rides_db.append(ride)
    return ride
