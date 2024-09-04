from fastapi import FastAPI, HTTPException, Request, Response
import requests
from jose import jwt, JWTError, ExpiredSignatureError
from datetime import datetime, timezone

SECRET_KEY = "12345"
ALGORITHM = "HS256"
AUTH_SERVICE_URL = "http://127.0.0.1:8002"

app = FastAPI()

async def jwt_validation_middleware(request: Request, call_next):
    if request.url.path in ["/openapi.json", "/docs"]:
        return await call_next(request)
    
    authorization: str = request.headers.get("Authorization")
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid Authorization Scheme")

        # Check if the token looks like a valid JWT
        if len(token.split(".")) != 3:
            raise HTTPException(status_code=401, detail="Invalid token format")

        payload = validate_jwt(token)
        
        if payload == "expired":
            # Token is expired, try renewing it
            renew_response = requests.post(f"{AUTH_SERVICE_URL}/renew_token/", json={"token": token})
            if renew_response.status_code == 200:
                new_token = renew_response.json()["access_token"]
                response = await call_next(request)
                
                # Include the new token in the response headers
                response.headers["Authorization"] = f"Bearer {new_token}"
                return response
            else:
                raise HTTPException(status_code=401, detail="Token expired and renewal failed")
        elif payload is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return await call_next(request)

    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Authorization Header Format")

def validate_jwt(token: str):
    try:
        # Decode the token to get the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if exp:
            # Check if the token is expired
            exp_datetime = datetime.fromtimestamp(exp, tz=timezone.utc)
            current_time = datetime.now(timezone.utc)
            print(f"Token exp datetime: {exp_datetime}, Current time: {current_time}")
            if exp_datetime < current_time:
                print("Token expired")
                return "expired"
        print("Token valid")
        return payload
    except ExpiredSignatureError:
        print("Token expired due to ExpiredSignatureError")
        return "expired"
    except JWTError as e:
        print(f"Token invalid due to JWTError: {str(e)}")
        return None

app.middleware("http")(jwt_validation_middleware)

@app.get("/protected")
async def protected_route():
    return {"message": "This is a protected route"}
