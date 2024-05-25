from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    admin: bool

class TokenData(BaseModel):
    username: str | None = None


class UserFetch(BaseModel):
    id: int
    username: str
    admin: bool

        
class UserPatchSchema(BaseModel):
    admin: bool
    username: str

class UserBase(UserPatchSchema):
    password: str
    
class UserCreate(UserBase):
    pass

class User(UserBase):
    id: int
