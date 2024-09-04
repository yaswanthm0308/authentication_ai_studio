from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from jose import jwt, JWTError, ExpiredSignatureError
from . import crud, models, schemas
from .database import SessionLocal
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY = "12345"  # This should match the key in API Gateway
ALGORITHM = "HS256"
TOKEN_EXPIRATION_SECONDS = 100  # test

app = FastAPI()

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Endpoint to authenticate user and provide a JWT
@app.post("/login/")
def login_for_access_token(user_data: schemas.UserLogin, db: Session = Depends(get_db), request: Request = None):
    user = crud.authenticate_user(db, user_data.email, user_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Set a short expiration for testing
    access_token_expires = timedelta(seconds=TOKEN_EXPIRATION_SECONDS)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    
    # Store the token in the database with IP address and User-Agent
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get('user-agent')
    crud.store_token(db, user, access_token, ip_address=ip_address, user_agent=user_agent)

    return {"access_token": access_token, "token_type": "bearer"}

# Token renewal endpoint to provide a new JWT if  old one is expirrred
@app.post("/renew_token/")
async def renew_token(request: Request, db: Session = Depends(get_db)):
    logger.info("Received token renewal request")
    try:
        body = await request.json()
        token = body.get("token")
    except Exception as e:
        logger.error(f"Error reading request body: {e}")
        raise HTTPException(status_code=400, detail="Invalid request body")

    if not token:
        logger.error("Token is missing from the request")
        raise HTTPException(status_code=400, detail="Token is missing")

    try:
        #  decode the token to get user email
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_email = payload.get("sub")
        except ExpiredSignatureError:
            # If the token is expired, extract user email without verifying
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
            user_email = payload.get("sub")
        except JWTError as e:
            logger.error(f"Invalid token: {str(e)}")
            raise HTTPException(status_code=401, detail="Invalid token")

        # Find the user from the email
        user = crud.get_user_by_email(db, email=user_email)
        if not user:
            logger.error("User not found for email: %s", user_email)
            raise HTTPException(status_code=404, detail="User not found")

        # Ensure last login time is timezone
        last_login_time = user.lastlogintime.replace(tzinfo=timezone.utc) if user.lastlogintime.tzinfo is None else user.lastlogintime
        ten_days_after_login = last_login_time + timedelta(days=10)

        # Check if the token renewal is within the allowed time (examople 10 days)
        if datetime.now(timezone.utc) > ten_days_after_login:
            logger.warning("Token renewal period has expired for user: %s", user_email)
            raise HTTPException(status_code=401, detail="Token renewal period has expired")

        # Generate a new token
        new_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(seconds=TOKEN_EXPIRATION_SECONDS))

        # Update the token in the database
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get('user-agent')
        crud.update_token(db, user, new_token, ip_address=ip_address, user_agent=user_agent)

        logger.info("Token renewed successfully for user: %s", user_email)
        return {"access_token": new_token, "token_type": "bearer"}

    except JWTError as e:
        logger.error("Invalid token: %s", str(e))
        raise HTTPException(status_code=401, detail="Invalid token")

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Example endpoint to revoke a token
@app.post("/revoke_token/")
def revoke_token(token: str, db: Session = Depends(get_db)):
    result = crud.revoke_token(db, token)
    if result:
        return {"message": "Token revoked successfully"}
    else:
        raise HTTPException(status_code=404, detail="Token not found or already inactive")
