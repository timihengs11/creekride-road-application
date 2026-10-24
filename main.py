from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "creekride-secret-2025"
ALGORITHM = "HS256"

app = FastAPI(title="CreekRide Road API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from passlib.context import CryptContext
import bcrypt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fix for bcrypt 4+ bug
def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

users_db = {}
rides_db = []
user_id_counter = 1
ride_id_counter = 1

class UserRegister(BaseModel):
    email: str; password: str; full_name: str
class Token(BaseModel):
    access_token: str; token_type: str
class RideCreate(BaseModel):
    pickup_lat: float; pickup_lng: float; dropoff_lat: float; dropoff_lng: float
class RideOut(BaseModel):
    id: int; rider_id: int; pickup_lat: float; pickup_lng: float; dropoff_lat: float; dropoff_lng: float; price: int; status: str = "pending"

def get_password_hash(p): return pwd_context.hash(p)
def verify_password(p, h): return pwd_context.verify(p, h)
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = users_db.get(payload.get("sub"))
        if not user: raise HTTPException(status_code=401, detail="Not authenticated")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Not authenticated")

@app.post("/register")
def register(user: UserRegister):
    global user_id_counter
    if user.email in users_db: raise HTTPException(status_code=400, detail="Email already registered")
    users_db[user.email] = {"id": user_id_counter, "email": user.email, "full_name": user.full_name, "hashed_password": get_password_hash(user.password)}
    user_id_counter += 1
    return {"id": users_db[user.email]["id"], "email": user.email, "full_name": user.full_name}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]): raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token(data={"sub": user["email"]}, expires_delta=timedelta(minutes=60))
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def read_me(current_user: dict = Depends(get_current_user)):
    return {"id": current_user["id"], "email": current_user["email"], "full_name": current_user["full_name"]}

@app.post("/rides", response_model=RideOut)
def create_ride(ride: RideCreate, current_user: dict = Depends(get_current_user)):
    global ride_id_counter
    new_ride = {"id": ride_id_counter, "rider_id": current_user["id"], "pickup_lat": ride.pickup_lat, "pickup_lng": ride.pickup_lng, "dropoff_lat": ride.dropoff_lat, "dropoff_lng": ride.dropoff_lng, "price": 1500, "status": "pending"}
    rides_db.append(new_ride); ride_id_counter += 1
    return new_ride

@app.get("/rides", response_model=List[RideOut])
def get_rides(current_user: dict = Depends(get_current_user)):
    return [r for r in rides_db if r["rider_id"] == current_user["id"]]
