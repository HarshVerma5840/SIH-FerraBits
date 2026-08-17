from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_password_hash, verify_password, create_access_token, get_current_user
from backend.app.models.database import User, Role
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["Authentication"])

class RegisterSchema(BaseModel):
    username: str
    password: str
    email: str = None
    role: str = "DEVELOPER"

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    existing = db.query(User).filter_by(username=data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
        
    # Get or create role
    role_name = data.role.upper()
    role_obj = db.query(Role).filter_by(name=role_name).first()
    if not role_obj:
        role_obj = Role(name=role_name, permissions="*")
        db.add(role_obj)
        db.commit()
        db.refresh(role_obj)
        
    hashed = get_password_hash(data.password)
    user = User(
        username=data.username,
        email=data.email,
        password_hash=hashed,
        role_id=role_obj.id
    )
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}

@router.post("/login", response_model=LoginResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
        
    role = db.query(Role).get(user.role_id)
    role_name = role.name if role else "VIEWER"
    
    token = create_access_token(data={"sub": user.username, "role": role_name})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": role_name
    }

@router.get("/me")
def get_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    role = db.query(Role).get(current_user.role_id)
    return {
        "username": current_user.username,
        "email": current_user.email,
        "role": role.name if role else "VIEWER"
    }
