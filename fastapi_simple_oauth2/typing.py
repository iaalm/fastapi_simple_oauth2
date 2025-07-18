from typing import Any, Dict, TypedDict


class TokenResponse(TypedDict):
    access_token: str
    token_type: str
    expires_in: int


ClaimsSet = Dict[str, Any]
