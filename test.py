import pytest
import time
from datetime import datetime, timedelta, timezone

from main import app, key_manager, KeyPair

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks_returns_keys(client):
    # Ensure at least one active key
    key_manager.add_new_key()
    rv = client.get("/jwks")
    assert rv.status_code == 200
    data = rv.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) > 0

def test_auth_returns_token(client): 
    key_manager.add_new_key()
    rv = client.post("/auth")
    assert rv.status_code == 200
    data = rv.get_json()
    assert "token" in data

def test_auth_expired_returns_token_or_error(client):
    # Add an expired key
    expired_key = KeyPair(
        private_key=key_manager.generate_keypair().private_key,
        public_key=key_manager.generate_keypair().public_key,
        kid="expired-kid",
        expiry=datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    key_manager.keys.append(expired_key)
    rv = client.post("/auth?expired=1")
    data = rv.get_json()
    # Returns a token or an error if no expired key is available
    assert rv.status_code in (200, 400)
    assert "token" in data or "error" in data

def test_auth_no_active_key(client):
    # Remove all active keys
    key_manager.keys = []
    rv = client.post("/auth")
    assert rv.status_code == 500
    data = rv.get_json()
    assert "error" in data

def test_well_known_jwks_returns_keys(client):
    key_manager.add_new_key()
    rv = client.get("/.well-known/jwks.json")
    assert rv.status_code == 200
    data = rv.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)

def test_well_known_jwks_valid_kid(client):
    key_manager.add_new_key()
    active_keys = key_manager.get_active_keys()
    if active_keys:
        kid = active_keys[0].kid
        rv = client.get(f"/.well-known/jwks.json?kid={kid}")
        assert rv.status_code == 200
        data = rv.get_json()
        assert data["valid"] is True
        assert "key" in data
        assert data["key"]["kid"] == kid

def test_well_known_jwks_invalid_kid(client):
    rv = client.get("/.well-known/jwks.json?kid=nonexistentkid")
    assert rv.status_code == 404
    data = rv.get_json()
    assert data["valid"] is False

def test_jwks_method_not_allowed(client):
    rv = client.post("/jwks")
    assert rv.status_code == 405

def test_auth_method_not_allowed(client):
    rv = client.get("/auth")
    assert rv.status_code == 405

def test_not_found(client):
    rv = client.get("/notarealendpoint")
    assert rv.status_code == 404