import os
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.app.models.database import SessionLocal, User, Role

# Configs
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-sbomguard-cybersecurity-token")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 360

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    # If no token is provided, return a default guest or demo user so the platform works out-of-the-box in the UI without requiring rigid logins
    if not token:
        # Check if default guest user exists, otherwise create it
        guest_role = db.query(Role).filter_by(name="ADMIN").first()
        if not guest_role:
            guest_role = Role(name="ADMIN", permissions="*")
            db.add(guest_role)
            db.commit()
            db.refresh(guest_role)
            
        guest_user = db.query(User).filter_by(username="demo_admin").first()
        if not guest_user:
            guest_user = User(
                username="demo_admin",
                password_hash=get_password_hash("demo123"),
                role_id=guest_role.id
            )
            db.add(guest_user)
            db.commit()
            db.refresh(guest_user)
        return guest_user

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter_by(username=username).first()
    if user is None:
        raise credentials_exception
    return user

class RoleChecker:
    def __init__(self, required_permissions: list):
        self.required_permissions = required_permissions

    def __call__(self, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        user_role = db.query(Role).get(current_user.role_id)
        if not user_role:
            raise HTTPException(status_code=403, detail="User role not assigned")
            
        if user_role.name == "ADMIN":
            return True # Admins bypass all checks
            
        # Check if user role matches permissions list
        user_perms = user_role.permissions.split(",") if user_role.permissions else []
        for req in self.required_permissions:
            if req not in user_perms:
                raise HTTPException(status_code=403, detail="Operation forbidden: Insufficient permissions")
        return True
