from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()

# Secret key to encode the JWT
SECRET_KEY = "12345"
ALGORITHM = "HS256"

class TokenData(BaseModel):
    username: str

# Function to create a new JWT token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Route to validate and refresh the token
@app.post("/token/refresh")
async def refresh_token(request: Request):
    authorization: str = request.headers.get("Authorization")
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization Header")

    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
        # Check if the token is within the renewal period (e.g., 10 days)
        original_issue_time = datetime.fromtimestamp(payload.get("iat"))
        if datetime.utcnow() - original_issue_time > timedelta(days=10):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired and cannot be renewed")

        # Create a new token with a shorter expiration time (e.g., 1 hour)
        new_token = create_access_token({"sub": username}, expires_delta=timedelta(hours=1))
        return {"access_token": new_token}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("authorization_service.main:app", host="127.0.0.1", port=8001, reload=True)
