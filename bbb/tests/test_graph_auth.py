import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

import msal


CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
TENANT_ID = "common"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["Sites.ReadWrite.All", "Files.ReadWrite.All"]
TOKEN_CACHE_FILE = Path(__file__).resolve().parent / ".graph_token.json"


def _load_cached_token() -> Optional[Dict[str, Any]]:
    if not TOKEN_CACHE_FILE.exists():
        return None

    try:
        with TOKEN_CACHE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _save_cached_token(token_result: Dict[str, Any], existing_cache: Optional[Dict[str, Any]] = None) -> None:
    expires_in = int(token_result.get("expires_in", 3600))
    cache_payload: Dict[str, Any] = {
        "access_token": token_result["access_token"],
        "refresh_token": token_result.get("refresh_token")
        or (existing_cache or {}).get("refresh_token"),
        "expires_at": int(time.time()) + expires_in,
        "scopes": SCOPES,
    }

    with TOKEN_CACHE_FILE.open("w", encoding="utf-8") as f:
        json.dump(cache_payload, f, indent=2)


def _is_cached_token_valid(cache: Dict[str, Any]) -> bool:
    access_token = cache.get("access_token")
    expires_at = cache.get("expires_at")

    if not access_token or not isinstance(expires_at, int):
        return False

    # Add a 60-second buffer so near-expiry tokens are treated as expired.
    return expires_at > int(time.time()) + 60


def get_graph_token() -> str:
    app = msal.PublicClientApplication(client_id=CLIENT_ID, authority=AUTHORITY)

    cached = _load_cached_token()

    if cached and _is_cached_token_valid(cached):
        token = cached["access_token"]
        print(f"Authentication successful. Token starts with: {token[:20]}")
        return token

    if cached and cached.get("refresh_token"):
        refresh_result = app.acquire_token_by_refresh_token(
            refresh_token=cached["refresh_token"],
            scopes=SCOPES,
        )
        if "access_token" in refresh_result:
            _save_cached_token(refresh_result, existing_cache=cached)
            token = refresh_result["access_token"]
            print(f"Authentication successful. Token starts with: {token[:20]}")
            return token

        print(
            "Refresh token flow failed; falling back to device code flow. "
            f"Reason: {refresh_result.get('error_description', refresh_result)}"
        )

    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise RuntimeError(f"Failed to create device flow: {flow}")

    print("To authenticate, visit this URL in your browser:")
    print(flow["verification_uri"])
    print(f"Then enter this code: {flow['user_code']}")

    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Device code authentication failed: {result}")

    _save_cached_token(result, existing_cache=cached)
    token = result["access_token"]
    print(f"Authentication successful. Token starts with: {token[:20]}")
    return token


if __name__ == "__main__":
    token_value = get_graph_token()
    print(f"Token acquired: {token_value}")
