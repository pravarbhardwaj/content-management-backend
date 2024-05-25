from fastapi import FastAPI, Depends, Request, HTTPException, status, Response
from typing import Annotated, List
from datetime import timedelta, datetime, timezone
from fastapi.responses import JSONResponse
import jwt
from jwt.exceptions import InvalidTokenError

from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from db import get_db
from models import User
from schemas import Token, TokenData, UserCreate, UserFetch, UserPatchSchema
from passlib.context import CryptContext
from fastapi.encoders import jsonable_encoder

import environ
env = environ.Env()
environ.Env.read_env()

SECRET_KEY=env("SECRET_KEY")
ACCESS_TOKEN_EXPIRE=env("ACCESS_TOKEN_EXPIRE")
ALGORITHM=env("ALGORITHM")

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app = FastAPI()

ALLOWED_ORIGINS = '*' 

# handle CORS preflight requests
@app.options('/{rest_of_path:path}')
async def preflight_handler(request: Request, rest_of_path: str) -> Response:
    response = Response()
    response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, DELETE, OPTIONS, PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response

# set CORS headers
@app.middleware("http")
async def add_CORS_header(request: Request, call_next):
    response = await call_next(request)
    response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db, username: str, password: str):
    user = db.query(User).filter(User.username==username).first()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session= Depends(get_db)):
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
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = db.query(User).filter(User.username==token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

@app.post("/create_user")
async def user_create(data: UserCreate,  db: Session = Depends(get_db)):
    #Check if username already exists
    print(data)
    user = db.query(User).filter(User.username==data.username).first()
    if user:
        return JSONResponse({"status": False, "message": "Username Already Exists"})

    db_user = User(username=data.username,
                password=get_password_hash(data.password),
                admin=data.admin)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return JSONResponse({"status": True, "message": "User Created"})

@app.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer", username=user.username, admin=user.admin)


@app.get("/fetch_users")
def fetch_users(current_user: Annotated[User, Depends(get_current_user)],
                username: str | None = None, 
                admin: bool | None = None, db: Session = Depends(get_db)) -> List[UserFetch]:
    query = db.query(User).filter(User.id!=current_user.id)
    if username:
        print(username)
        query = query.filter(User.username.icontains(username))
    if admin:
        query = query.filter(User.admin==admin)

    return query

@app.get("/fetch_users/{user_id}")
def fetch_users(current_user: Annotated[User, Depends(get_current_user)],
                user_id: int, db: Session = Depends(get_db)) -> List[UserFetch]:
    return db.query(User).filter(User.id==user_id).first()

@app.delete("/user/{user_id}")
async def delete_user(current_user: Annotated[User, Depends(get_current_user)], 
                      user_id: int, db: Session = Depends(get_db)):
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    query = db.query(User).filter(User.id==user_id).first()
    db.delete(query)
    db.commit()
    return "User deleted successfully!"

@app.put("/user/{user_id}", status_code=202)
async def patch_user(current_user: Annotated[User, Depends(get_current_user)],
                     user_id: str, 
                     data: UserPatchSchema,
                     db: Session = Depends(get_db)):
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    db_user = db.query(User).filter(User.id==user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this id not found"
        )
    query = db.query(User).filter(User.username==data.username, User.id!=user_id).first()
    if query:
        return JSONResponse({"status": False, "message": "This username already exists."})
    data = jsonable_encoder(data)
    for dat in data: 
        if hasattr(db_user, dat):
            setattr(db_user, dat, data[dat])

    db.merge(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user