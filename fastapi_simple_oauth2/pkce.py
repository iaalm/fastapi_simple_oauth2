import base64
import hashlib
import logging
import secrets
import time
from functools import wraps
from typing import Any, Callable, Dict, Optional, cast
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from fastapi_simple_oauth2.typing import ClaimsSet, TokenResponse

logger = logging.getLogger(__name__)


class OAuth2PKCE:
    """OAuth2 PKCE flow implementation for FastAPI - Stateless version"""

    def __init__(
        self,
        secret_key: Optional[str] = None,
        enforce_redirect_uri_callback: Optional[Callable[[Optional[str]], str]] = None,
    ):
        """
        Initialize OAuth2 PKCE middleware

        Args:
            secret_key: Secret key for JWT signing. If None, a random key will be generated.
        """
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = "HS256"
        self.enforce_redirect_uri_callback = enforce_redirect_uri_callback

    def _generate_code_challenge(self, code_verifier: str) -> str:
        """Generate code challenge from code verifier using SHA256"""
        sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(sha256_hash).decode()

    def _create_authorization_code(
        self,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        state: Optional[str] = None,
        expires_in: int = 300,
        claims: ClaimsSet = {},
    ) -> str:
        """Create a JWT-based authorization code"""
        payload = {
            "type": "authorization_code",
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
            "iat": int(time.time()),
            "exp": int(time.time()) + expires_in,
            "iss": "fastapi-oauth2-pkce",
            **claims,
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def _verify_authorization_code(self, code: str) -> ClaimsSet:
        """Verify and decode an authorization code JWT"""
        payload = self._verify_jwt_token(code)
        if payload.get("type") != "authorization_code":
            raise HTTPException(
                status_code=400, detail="Invalid authorization code type"
            )

        return payload

    def _create_jwt_token(self, claims: ClaimsSet, expires_in: int = 3600) -> str:
        """Create a JWT token with the given claims"""
        payload = {
            **claims,
            "iat": int(time.time()),
            "exp": int(time.time()) + expires_in,
            "iss": "fastapi-oauth2-pkce",
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def _verify_jwt_token(self, token: str) -> ClaimsSet:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            # TODO: check if we need following code
            # if payload.get("exp", 0) < time.time():
            #     raise HTTPException(
            #         status_code=400, detail="Token has expired"
            #     )
            return cast(ClaimsSet, payload)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

    def register_oauth_routes(
        self,
        app: FastAPI,
        validate_callback: Callable[[str, str], Optional[ClaimsSet]],
    ) -> FastAPI:
        """
        Register OAuth routes with the FastAPI application

        Args:
            app: FastAPI application instance
            validate_callback: Function that takes username and password, returns claims dict or None
        """

        @app.post("/token")
        async def token(
            grant_type: str = Form(..., description="Must be 'authorization_code'"),
            code: str = Form(..., description="Authorization code"),
            code_verifier: str = Form(..., description="PKCE code verifier"),
        ) -> TokenResponse:
            """OAuth2 token endpoint"""

            if grant_type != "authorization_code":
                raise HTTPException(
                    status_code=400, detail="grant_type must be 'authorization_code'"
                )

            # Verify and decode the authorization code
            auth_code_data = self._verify_authorization_code(code)

            # Verify PKCE
            expected_challenge = self._generate_code_challenge(code_verifier)
            if expected_challenge != auth_code_data["code_challenge"]:
                raise HTTPException(status_code=400, detail="Invalid code verifier")

            auth_code_data.pop("code_challenge")
            auth_code_data.pop("code_challenge_method")
            auth_code_data.pop("redirect_uri")
            auth_code_data["type"] = "access_token"
            # Create access token
            access_token = self._create_jwt_token(auth_code_data)

            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            }

        @app.post("/login")
        async def login(
            username: str = Form(...),
            password: str = Form(...),
            redirect_uri: str = Form(...),
            code_challenge: str = Form(...),
            code_challenge_method: str = Form(...),
            state: Optional[str] = Form(None),
            client_id: Optional[str] = Form(None),
        ) -> RedirectResponse:
            """Login endpoint that validates credentials and returns authorization code"""
            # Validate credentials using the callback
            claims = validate_callback(username, password)
            if claims is None:
                raise HTTPException(status_code=401, detail="Invalid credentials")

            # Validate PKCE parameters
            if code_challenge_method != "S256":
                raise HTTPException(
                    status_code=400, detail="code_challenge_method must be 'S256'"
                )

            # Create authorization code
            auth_code = self._create_authorization_code(
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                state=state,
                claims=claims,
            )

            # Build redirect URL with authorization code
            redirect_params = {"code": auth_code}
            if state:
                redirect_params["state"] = state

            if self.enforce_redirect_uri_callback:
                expected_redirect_uri = self.enforce_redirect_uri_callback(client_id)
                if expected_redirect_uri != redirect_uri:
                    raise HTTPException(status_code=400, detail="Invalid redirect URI")

            redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
            return RedirectResponse(url=redirect_url)

        return app

    def require_claims_dependency(
        self, required_claims: ClaimsSet
    ) -> Callable[[str], ClaimsSet]:
        """
        FastAPI dependency to require specific claims in the JWT token

        Args:
            required_claims: Dictionary of required claims and their expected values

        Returns:
            FastAPI dependency function that validates JWT claims
        """
        auth_scheme = HTTPBearer()
        def dependency(
            authorization: HTTPAuthorizationCredentials = Depends(auth_scheme)
        ) -> ClaimsSet:
            token = authorization.credentials
            payload = self._verify_jwt_token(token)
            if payload.get("type") != "access_token":
                raise HTTPException(status_code=401, detail="Invalid token type")

            # Check required claims
            for claim, expected_value in required_claims.items():
                if claim not in payload:
                    raise HTTPException(
                        status_code=403, detail=f"Missing required claim: {claim}"
                    )
                if isinstance(expected_value, list):
                    if payload[claim] not in expected_value:
                        raise HTTPException(
                            status_code=403, detail=f"Invalid claim value for: {claim}"
                        )
                elif expected_value is not None and payload[claim] != expected_value:
                    raise HTTPException(
                        status_code=403, detail=f"Invalid claim value for: {claim}"
                    )
                else:
                    raise HTTPException(
                        status_code=500, detail=f"Invalid claim value for: {claim}"
                    )

            return payload

        return dependency


# Convenience functions for easier usage
def register_oauth_route(
    app: FastAPI,
    validate_callback: Callable[[str, str], Optional[ClaimsSet]],
    key: Optional[str] = None,
    enforce_redirect_uri_callback: Optional[Callable[[Optional[str]], str]] = None,
) -> OAuth2PKCE:
    """
    Register OAuth routes with the FastAPI application

    Args:
        app: FastAPI application instance
        validate_callback: Function that takes username and password, returns claims dict or None
        key: Secret key for JWT signing (optional)
    """
    if key is None:
        logger.warning("No secret key provided, generating a random one")
        key = secrets.token_urlsafe(32)
    oauth = OAuth2PKCE(
        secret_key=key, enforce_redirect_uri_callback=enforce_redirect_uri_callback
    )
    oauth.register_oauth_routes(app, validate_callback)
    return oauth


def require_claims_dependency(
    required_claims: ClaimsSet, key: str
) -> Callable[[str], ClaimsSet]:
    """
    FastAPI dependency to require specific claims in the JWT token

    Args:
        required_claims: Dictionary of required claims and their expected values
        key: Secret key for JWT signing

    Returns:
        FastAPI dependency function that validates JWT claims
    """
    oauth = OAuth2PKCE(secret_key=key)
    return oauth.require_claims_dependency(required_claims)
