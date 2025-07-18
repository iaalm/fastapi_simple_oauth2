#!/usr/bin/env python3
"""
Simple tests for the OAuth2 PKCE implementation
"""

import base64
import hashlib
import secrets
import unittest

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_simple_oauth2 import OAuth2PKCE, register_oauth_route


class TestOAuth2PKCE(unittest.TestCase):
    """Test cases for OAuth2 PKCE implementation"""

    def setUp(self):
        app = FastAPI()

        self.test_user = ("test", "password", {"role": "user"})
        self.admin_user = ("admin", "password", {"role": "admin"})
        users = [self.test_user, self.admin_user]

        # Mock user validation
        def validate_user(username: str, password: str):
            for user in users:
                if user[0] == username and user[1] == password:
                    return user[2]
            return None

        # Register OAuth routes
        oauth = register_oauth_route(app, validate_callback=validate_user)
        login_require = oauth.require_claims_dependency({})
        admin_require = oauth.require_claims_dependency({"role": "admin"})

        @app.get("/protected")
        async def protected(user_cliaims: dict = Depends(login_require)):
            return {"message": "success"}

        @app.get("/admin")
        async def protected(user_cliaims: dict = Depends(admin_require)):
            return {"message": "success"}

        self.client = TestClient(app)

    def test_oauth_flow(self):
        """Test complete OAuth2 flow"""

        # response = client.get("/protected")
        # self.assertEqual(response.status_code, 401)

        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode()
        # Test authorization endpoint
        response = self.client.post(
            "/login",
            data={
                "response_type": "code",
                "username": self.test_user[0],
                "password": self.test_user[1],
                "redirect_uri": "/protected",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 307)
        self.assertIn("code=", response.headers["location"])

        token_response = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": response.headers["location"].split("code=")[1],
                "code_verifier": code_verifier,
            },
        )

        self.assertEqual(token_response.status_code, 200)
        self.assertIn("access_token", token_response.json())
        self.assertIn("expires_in", token_response.json())
        self.assertEqual(token_response.json()["token_type"], "Bearer")

        response = self.client.get(
            "/protected",
            headers={
                "Authorization": f"Bearer {token_response.json()['access_token']}"
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "success"})

        response = self.client.get(
            "/admin",
            headers={
                "Authorization": f"Bearer {token_response.json()['access_token']}"
            },
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    # Run the tests
    unittest.main()
