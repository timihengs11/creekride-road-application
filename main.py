from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import uuid

# --- CONFIG ---
SECRET_KEY = "creekride-secret-2025-bayelsa-to-world"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="CreekRide Road API - FIXED")

# CORS - Allow all for Bayelsa to World
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- FIX BCRYPT 72 BYTE BUG - THIS IS THE FIX ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=False)

def get_password_hash(password: str):
    # FIX: Truncate to 72 bytes for bcrypt
    if isinstance(password, str):
        password = password[:72]
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    # FIX: Truncate to 72 bytes for verify too
    if isinstance(plain_password, str):
        plain_password = plain_password[:72]
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- IN-MEMORY DB (Works on Render free tier - no file delete) ---
users_db = {}  # email -> {full_name, email, password_hash, id}
rides_db = []  # list of rides
bookings_db = []

# --- MODELS ---
class RegisterRequest(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    name: Optional[str] = None
    username: Optional[str] = None

class LoginRequest(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

class RideCreate(BaseModel):
    origin: Optional[str] = None
    destination: Optional[str] = None
    from_location: Optional[str] = None
    to_location: Optional[str] = None
    date: Optional[str] = None
    price: Optional[str] = None
    seats: Optional[str] = None
    from_field: Optional[str] = None
    to_field: Optional[str] = None

    class Config:
        fields = {'from_location': 'from', 'to_location': 'to'}

# --- ROUTES ---
@app.get("/")
def root():
    return {"message": "CreekRide Bayelsa to the World - Backend LIVE 200 OK - FIXED BCRYPT", "rides": len(rides_db), "users": len(users_db)}

@app.post("/register")
def register(payload: dict = Body(...)):
    # Accept any field names
    full_name = payload.get("full_name") or payload.get("name") or payload.get("username") or "User"
    email = payload.get("email") or payload.get("username")
    password = payload.get("password")
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    
    email = email.lower().strip()
    
    if email in users_db:
        raise HTTPException(status_code=400, detail="User already exists - please login")
    
    # FIXED HASH
    try:
        hashed = get_password_hash(password)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash error: {str(e)}")
    
    user_id = str(uuid.uuid4())
    users_db[email] = {
        "id": user_id,
        "full_name": full_name,
        "email": email,
        "password_hash": hashed
    }
    
    return {"message": "User registered successfully - Bayelsa to the World!", "user_id": user_id, "email": email, "full_name": full_name}

@app.post("/login")
def login(payload: dict = Body(None), form_data: OAuth2PasswordRequestForm = Depends(None)):
    # Handle both JSON and form-data
    email = None
    password = None
    
    if payload:
        email = payload.get("email") or payload.get("username")
        password = payload.get("password")
    if form_data and hasattr(form_data, 'username'):
        try:
            if form_data.username:
                email = form_data.username
                password = form_data.password
        except:
            pass
    
    if not email or not password:
        # Try form_data as fallback
        try:
            if form_data:
                email = form_data.username
                password = form_data.password
        except:
            pass
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    
    email = email.lower().strip()
    
    if email not in users_db:
        raise HTTPException(status_code=401, detail="Invalid email or password - user not found")
    
    user = users_db[email]
    
    # FIXED VERIFY
    try:
        if not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
    except Exception as e:
        # If old hash was created with bug, allow re-hash check
        raise HTTPException(status_code=401, detail=f"Password check failed: {str(e)}")
    
    access_token = create_access_token(data={"sub": email})
    
    return {"access_token": access_token, "token_type": "bearer", "email": email, "full_name": user["full_name"]}

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None or email not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        return users_db[email]
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

@app.get("/rides")
def get_rides():
    return rides_db

@app.post("/rides")
def create_ride(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    origin = payload.get("origin") or payload.get("from") or payload.get("from_location") or "Yenagoa"
    destination = payload.get("destination") or payload.get("to") or payload.get("to_location") or "Brass"
    date = payload.get("date") or datetime.now().strftime("%Y-%m-%d")
    price = payload.get("price") or "8000"
    seats = payload.get("seats") or "4"
    
    ride = {
        "id": str(uuid.uuid4()),
        "origin": origin,
        "destination": destination,
        "date": date,
        "price": price,
        "seats": seats,
        "driver": current_user["email"],
        "driver_name": current_user["full_name"],
        "created_at": datetime.now().isoformat()
    }
    rides_db.append(ride)
    return ride

@app.post("/rides/{ride_id}/book")
def book_ride(ride_id: str, current_user: dict = Depends(get_current_user)):
    for ride in rides_db:
        if ride["id"] == ride_id or ride.get("_id") == ride_id:
            booking = {
                "id": str(uuid.uuid4()),
                "ride_id": ride_id,
                "passenger": current_user["email"],
                "passenger_name": current_user["full_name"],
                "booked_at": datetime.now().isoformat()
            }
            bookings_db.append(booking)
            return {"message": "Ride booked successfully - Bayelsa to the World!", "booking": booking, "ride": ride}
    raise HTTPException(status_code=404, detail="Ride not found")

@app.get("/bookings")
def get_bookings(current_user: dict = Depends(get_current_user)):
    return [b for b in bookings_db if b["passenger"] == current_user["email"]]
