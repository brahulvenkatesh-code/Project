import os
import jwt
import logging
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Header
from typing import Optional

# Security Configuration
SECRET_KEY = os.environ.get("API_JWT_SECRET", "super-secret-risk-governance-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Roles definition
ROLES = {
    "ADMIN": ["analyze", "audit", "manage_users"],
    "AUDITOR": ["audit", "read_decisions"],
    "USER": ["analyze"],
    "SYSTEM": ["analyze", "internal_call"]
}

logger = logging.getLogger("access_control")

class AccessManager:
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

    @staticmethod
    def check_permissions(payload: dict, required_permission: str):
        role = payload.get("role", "USER")
        permissions = ROLES.get(role, [])
        if required_permission not in permissions:
            logger.warning(f"Permission denied: role {role} attempted {required_permission}")
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return True

    @staticmethod
    def abac_authorize(payload: dict, resource_owner_id: str):
        """Attribute-Based Access Control logic."""
        user_id = payload.get("sub")
        role = payload.get("role")
        
        # Admin can see everything
        if role == "ADMIN":
            return True
            
        # Users can only see their own resources
        if user_id == resource_owner_id:
            return True
            
        raise HTTPException(status_code=403, detail="Resource access denied (ABAC violation)")

def get_current_user_payload(authorization: str):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    # Handle various prefix formats (Bearer, bearer, or none)
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    else:
        token = authorization.strip()
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
