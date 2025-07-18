# FastAPI Simple OAuth2 PKCE

A lightweight, stateless OAuth2 middleware for FastAPI applications with PKCE (Proof Key for Code Exchange) flow support. This plugin provides a simple way to implement OAuth2 authorization in your FastAPI applications without the complexity of full OAuth2 providers.

## Features

- **PKCE Flow Support**: Implements OAuth2 PKCE flow for secure authorization
- **JWT Tokens**: Stateless authentication using JWT tokens
- **Custom Claims**: Support for custom claims in JWT tokens
- **Simple Integration**: Easy to integrate with existing FastAPI applications
- **Single Tenant**: Designed for single-tenant applications
- **No Database Required**: In-memory storage for development (can be extended for production)

## Installation

```bash
pip install fastapi-simple-oauth2
```

## Quick Start

```python
from fastapi import FastAPI
from fastapi_simple_oauth2 import register_oauth_route, require_claim

app = FastAPI()

# Define your user validation function
def validate_user(username: str, password: str):
    # Your authentication logic here
    if username == "admin" and password == "password":
        return {"user_id": "admin", "role": "admin"}
    return None

# Register OAuth routes
oauth = register_oauth_route(app, validate_callback=validate_user)

# Protected endpoint
@app.get("/protected")
@require_claim({"role": "admin"})
async def protected_route():
    return {"message": "Access granted!"}
```

## API Reference

### `register_oauth_route(app, validate_callback, key=None)`

Registers OAuth2 routes with your FastAPI application.

**Parameters:**
- `app` (FastAPI): Your FastAPI application instance
- `validate_callback` (Callable): Function that validates username/password and returns claims
- `key` (str, optional): Secret key for JWT signing. If not provided, a random key will be generated.

**Returns:**
- `OAuth2PKCE`: OAuth2 instance for further configuration

### `require_claim(required_claims)`

Decorator to protect endpoints with specific claim requirements.

**Parameters:**
- `required_claims` (dict): Dictionary of required claims and their expected values

## OAuth2 Flow

### 1. Authorization Request

The client initiates the OAuth2 flow by redirecting the user to the `/authorize` endpoint:

```
GET /authorize?response_type=code&client_id=your_client&redirect_uri=http://localhost:3000/callback&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256&state=random_state
```

**Required Parameters:**
- `response_type`: Must be "code"
- `client_id`: Your client identifier
- `redirect_uri`: Where to redirect after authorization
- `code_challenge`: PKCE code challenge
- `code_challenge_method`: Must be "S256"

### 2. User Authentication

The user is redirected to your application where they can authenticate. After successful authentication, the user is redirected back with an authorization code.

### 3. Token Exchange

The client exchanges the authorization code for an access token:

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTHORIZATION_CODE&code_verifier=CODE_VERIFIER&client_id=your_client&redirect_uri=http://localhost:3000/callback
```

**Response:**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### 4. Using the Access Token

Include the access token in the Authorization header for protected endpoints:

```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

## Example Usage

### Basic Setup

```python
from fastapi import FastAPI
from fastapi_simple_oauth2 import register_oauth_route, require_claim

app = FastAPI()

# Mock user database
USERS = {
    "admin": {"password": "admin123", "claims": {"role": "admin"}},
    "user": {"password": "user123", "claims": {"role": "user"}}
}

def validate_user(username: str, password: str):
    user = USERS.get(username)
    if user and user["password"] == password:
        return user["claims"]
    return None

# Register OAuth routes
oauth = register_oauth_route(app, validate_callback=validate_user)

# Protected endpoints
@app.get("/admin")
@require_claim({"role": "admin"})
async def admin_only():
    return {"message": "Admin access granted!"}

@app.get("/user")
@require_claim({"role": "user"})
async def user_only():
    return {"message": "User access granted!"}
```

### Frontend Integration

Here's an example of how to implement the OAuth2 flow in a frontend application:

```javascript
// Generate PKCE code verifier and challenge
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

function generateCodeChallenge(verifier) {
    const hash = crypto.subtle.digestSync('SHA-256', new TextEncoder().encode(verifier));
    return base64URLEncode(new Uint8Array(hash));
}

// Start OAuth2 flow
async function startOAuthFlow() {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    // Store code verifier for later use
    localStorage.setItem('code_verifier', codeVerifier);
    
    const params = new URLSearchParams({
        response_type: 'code',
        client_id: 'your_client_id',
        redirect_uri: 'http://localhost:3000/callback',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: generateRandomState()
    });
    
    window.location.href = `http://localhost:8000/authorize?${params}`;
}

// Exchange code for token
async function exchangeCodeForToken(code) {
    const codeVerifier = localStorage.getItem('code_verifier');
    
    const response = await fetch('http://localhost:8000/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            code_verifier: codeVerifier,
            client_id: 'your_client_id',
            redirect_uri: 'http://localhost:3000/callback'
        })
    });
    
    const tokenData = await response.json();
    localStorage.setItem('access_token', tokenData.access_token);
}
```

## Security Considerations

1. **Secret Key**: Always use a strong, unique secret key in production
2. **HTTPS**: Use HTTPS in production to protect tokens in transit
3. **Token Expiration**: Tokens expire after 1 hour by default
4. **Code Cleanup**: Authorization codes are automatically cleaned up after use
5. **State Parameter**: Use the state parameter to prevent CSRF attacks

## Production Considerations

For production use, consider:

1. **Persistent Storage**: Replace in-memory storage with Redis or a database
2. **Token Refresh**: Implement token refresh functionality
3. **Rate Limiting**: Add rate limiting to prevent abuse
4. **Logging**: Add comprehensive logging for security monitoring
5. **CORS**: Configure CORS properly for your frontend domains

## License

MIT License - see LICENSE file for details.