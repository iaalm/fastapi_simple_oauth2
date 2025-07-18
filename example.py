#!/usr/bin/env python3
"""
Example usage of the FastAPI Simple OAuth2 PKCE plugin
"""

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from fastapi_simple_oauth2 import register_oauth_route, require_claim

# Create FastAPI app
app = FastAPI(title="OAuth2 PKCE Example")

# Mock user database (in production, use a real database)
USERS = {
    "admin": {
        "password": "admin123",
        "claims": {
            "user_id": "admin",
            "role": "admin",
            "permissions": ["read", "write", "delete"],
        },
    },
    "user": {
        "password": "user123",
        "claims": {"user_id": "user", "role": "user", "permissions": ["read"]},
    },
}


def validate_user(username: str, password: str):
    """Validate user credentials and return claims"""
    user = USERS.get(username)
    if user and user["password"] == password:
        return user["claims"]
    return None


# Register OAuth routes with custom secret key
oauth = register_oauth_route(
    app,
    validate_callback=validate_user,
    key="your-secret-key-here-change-in-production",
)


# Protected endpoint requiring admin role
@app.get("/admin")
async def admin_only(
    user_cliaims: dict = Depends(oauth.require_claims_dependency({"role": "admin"})),
):
    return {"message": "Admin access granted!", "data": "sensitive admin data"}


# Protected endpoint requiring read permission
@app.get("/data")
async def read_data(
    user_cliaims: dict = Depends(
        oauth.require_claims_dependency({"permissions": ["read"]})
    ),
):
    return {"message": "Data access granted!", "data": "some data"}


# Simple login form
@app.get("/login", response_class=HTMLResponse)
async def login_form():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth2 Login</title>
    </head>
    <body>
        <h1>OAuth2 Login</h1>
        <form action="/login" method="post">
            <p>
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </p>
            <p>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </p>
            <p>
                <label for="code">Authorization Code:</label>
                <input type="text" id="code" name="code" required>
            </p>
            <p>
                <label for="redirect_uri">Redirect URI:</label>
                <input type="text" id="redirect_uri" name="redirect_uri" required>
            </p>
            <button type="submit">Login</button>
        </form>
        
        <h2>Test Users:</h2>
        <ul>
            <li>Username: admin, Password: admin123 (Admin role)</li>
            <li>Username: user, Password: user123 (User role)</li>
        </ul>
    </body>
    </html>
    """


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
