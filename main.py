
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- CONFIG ---
SECRET_KEY = "creekride-secret-2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="CreekRide Road API")

# CORS - Allow frontend creekride-frontend.onrender.com
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- SECURITY ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# In-memory DB (Render free instance - resets on restart, use Postgres later)
users_db = {}  # email -> {full_name, email, hashed_password}
rides_db = []  # list of rides

class RegisterRequest(BaseModel):
    full_name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class RideRequest(BaseModel):
    origin: Optional[str] = None
    destination: Optional[str] = None
    from_location: Optional[str] = None
    to_location: Optional[str] = None
    from_: Optional[str] = None
    to: Optional[str] = None
    date: Optional[str] = None
    seats: Optional[int] = 1
    price: Optional[str] = None
    
    class Config:
        fields = {'from_': 'from'}

    # Allow extra fields like from, to, origin, destination
    def get_from(self):
        return self.origin or self.from_location or self.from_ or getattr(self, 'from', None) or "Warri"
    
    def get_to(self):
        return self.destination or self.to_location or self.to or getattr(self, 'to', None) or "Burutu"

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        if email not in users_db:
            raise HTTPException(status_code=401, detail="User not found")
        return users_db[email]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/")
def root():
    return {"message": "CreekRide Road API is Live!", "status": "200 OK", "backend": "creekride-road-application-2.onrender.com"}

@app.post("/register")
def register(req: RegisterRequest):
    email = req.email.lower().strip()
    if email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    users_db[email] = {
        "full_name": req.full_name,
        "email": email,
        "hashed_password": get_password_hash(req.password)
    }
    print(f"Registered: {email} - {req.full_name} - 200 SUCCESS")
    return {"message": "200 OK LIVE Rides - User registered", "status": "200", "user": req.full_name, "email": email}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), req: Optional[LoginRequest] = None):
    # Support both JSON and form-data
    if req:
        email = req.email.lower().strip()
        password = req.password
    else:
        # OAuth2 form uses username field for email
        email = form_data.username.lower().strip()
        password = form_data.password
    
    user = users_db.get(email)
    if not user or not verify_password(password, user["hashed_password"]):
        # Also check if req provided JSON login
        # Try to get from body if not form
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer", "user": user["full_name"]}

# Extra JSON login endpoint for frontend
@app.post("/login-json")
def login_json(req: LoginRequest):
    email = req.email.lower().strip()
    user = users_db.get(email)
    if not user or not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer", "user": user["full_name"]}

@app.get("/me")
def me(current_user = Depends(get_current_user)):
    return {"email": current_user["email"], "full_name": current_user["full_name"]}

@app.get("/rides")
def get_rides():
    return rides_db

@app.post("/rides")
def create_ride(req: dict, current_user = Depends(get_current_user)):
    # Accept any field names
    ride = {
        "id": len(rides_db) + 1,
        "origin": req.get("origin") or req.get("from") or req.get("from_location") or "Warri",
        "destination": req.get("destination") or req.get("to") or req.get("to_location") or "Burutu",
        "date": req.get("date") or str(datetime.now().date()),
        "seats": req.get("seats") or 1,
        "price": req.get("price") or "5000",
        "driver": current_user["full_name"],
        "driver_email": current_user["email"]
    }
    rides_db.append(ride)
    return ride
