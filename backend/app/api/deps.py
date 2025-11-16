"""
Authentication and Authorization Utilities.

This module provides helper functions for:
- Extracting the current authenticated user from a JWT token
- Enforcing role-based permissions
- Utility checks for authentication state

It uses SQLAlchemy sessions, JWT decoding, and OAuth2 password flow.
"""

from typing import Optional, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import logging

from app.core.security import decode_access_token
from app.db.session import get_db
from app.db.models.user import User, UserRole

# OAuth2 scheme for extracting JWT token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Logger for debugging and tracing authentication flow
logger = logging.getLogger(__name__)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Returns the currently authenticated user based on a JWT token.

    Args:
        token (str | None):
            The JWT token extracted from the Authorization header.
        db (Session):
            SQLAlchemy database session used to query user records.

    Returns:
        User | None:
            - User instance if token is valid and user exists.
            - None if token is missing, invalid, or user does not exist.
    """

    # Log received token (for debugging only)
    logger.debug("Received token: %s", token)

    if not token:
        logger.warning("No token provided in Authorization header")
        return None

    # Decode the token and extract payload
    payload = decode_access_token(token)
    if not payload:
        logger.warning("Failed to decode access token")
        return None

    user_id = payload.get("sub")
    if user_id is None:
        logger.warning("Token payload missing 'sub' field")
        return None

    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        logger.warning("User not found for user_id=%s", user_id)
        return None

    logger.info("Authenticated user ID: %s", user.id)
    return user


def role_required(required_role: UserRole) -> Callable:
    """
    Creates a dependency function enforcing that the authenticated user
    has at least the given required role.

    Args:
        required_role (UserRole):
            The minimum role required to access the protected endpoint.

    Returns:
        Callable:
            A FastAPI dependency function.
    """

    def wrapper(
        current_user: Optional[User] = Depends(get_current_user)
    ) -> Optional[User]:
        if not current_user:
            logger.warning(
                "Authentication failed: No user provided or invalid token"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed. Please provide a valid token.",
            )

        # Compare roles by their numeric value (higher = more privileges)
        if current_user.role.value < required_role.value:
            logger.warning(
                "Permission denied: user_id=%s user_role=%s required=%s",
                current_user.id,
                current_user.role,
                required_role,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: required role '{required_role.value}'.",
            )

        logger.info(
            "Authorization success: user_id=%s has required role=%s",
            current_user.id,
            required_role,
        )
        return current_user

    return wrapper


def is_authenticated(user: Optional[User]) -> bool:
    """
    Utility function that returns True if the given user is authenticated.

    Args:
        user (User | None): User instance returned by get_current_user()

    Returns:
        bool: True if user is not None, False otherwise.
    """
    return user is not None
