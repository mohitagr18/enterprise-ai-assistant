"""
API Tests for the Sentinel AI HTTP endpoints.
"""

from __future__ import annotations

import json
import sys
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
import chromadb
from httpx import AsyncClient

# Mock out magic module to prevent libmagic import errors on systems without the C library
mock_magic = MagicMock()
sys.modules["magic"] = mock_magic

from sentinel.auth.routes import hash_password
from sentinel.config import Settings
from sentinel.main import app
from sentinel.dependencies import get_chroma_collection


@pytest.fixture
def mock_chroma_collection():
    """Create a temporary in-memory ChromaDB collection for testing."""
    client = chromadb.EphemeralClient()
    collection_name = f"test_api_{uuid.uuid4().hex}"
    collection = client.get_or_create_collection(collection_name, metadata={"hnsw:space": "cosine"})
    return collection


@pytest.fixture(autouse=True)
def override_chromadb(mock_chroma_collection):
    """Override the ChromaDB dependency to use the mock collection."""
    app.dependency_overrides[get_chroma_collection] = lambda: mock_chroma_collection
    yield


@pytest.fixture(autouse=True)
def mock_llm_guard_scanners():
    """Mock llm-guard inputs to avoid loading models or downloading weights."""
    mock_inj = MagicMock()
    mock_inj.scan.return_value = ("sanitized", True, 0.0)
    mock_tox = MagicMock()
    mock_tox.scan.return_value = ("sanitized", True, 0.0)
    mock_ban = MagicMock()
    mock_ban.scan.return_value = ("sanitized", True, 0.0)

    with patch("llm_guard.input_scanners.PromptInjection", return_value=mock_inj), \
         patch("llm_guard.input_scanners.Toxicity", return_value=mock_tox), \
         patch("llm_guard.input_scanners.BanTopics", return_value=mock_ban):
        yield


@pytest.mark.asyncio
async def test_health_endpoint(async_client: AsyncClient) -> None:
    """Verify public health endpoint returns healthy state and uptime."""
    r = await async_client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data
    assert "version" in data


@pytest.mark.asyncio
async def test_authentication_endpoints(async_client: AsyncClient) -> None:
    """Verify login validation, JWT issuance, and token refresh."""
    # 1. Login with correct credentials
    login_payload = {"username": "standarduser", "password": "userpass123"}
    r = await async_client.post("/auth/login", json=login_payload)
    assert r.status_code == 200
    tokens = r.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"

    # 2. Login with incorrect credentials
    bad_payload = {"username": "standarduser", "password": "wrongpassword"}
    r_bad = await async_client.post("/auth/login", json=bad_payload)
    assert r_bad.status_code == 401

    # 3. Refresh access token (must pass refresh token in Bearer header as well)
    refresh_payload = {"refresh_token": tokens["refresh_token"]}
    r_ref = await async_client.post(
        "/auth/refresh",
        json=refresh_payload,
        headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
    )
    assert r_ref.status_code == 200
    new_tokens = r_ref.json()
    assert "access_token" in new_tokens

    # 4. Logout (stateless confirm)
    r_out = await async_client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r_out.status_code == 200
    assert r_out.json()["message"] == "Logged out successfully"


@pytest.mark.asyncio
async def test_chat_pipeline_endpoint(
    async_client: AsyncClient,
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """Test POST /chat routing and security pipeline execution."""
    # Authenticate standard user
    login_r = await async_client.post(
        "/auth/login",
        json={"username": "standarduser", "password": "userpass123"},
    )
    access_token = login_r.json()["access_token"]

    # Setup OpenAI Mocks
    mock_choice = MagicMock()
    mock_choice.message.content = '{"response": "Yes, standard clearance policies apply."}'
    mock_completion = MagicMock(choices=[mock_choice])
    mock_chat_create = AsyncMock(return_value=mock_completion)

    mock_mod_result = MagicMock(flagged=False)
    mock_mod_response = MagicMock(results=[mock_mod_result])
    mock_mod_create = AsyncMock(return_value=mock_mod_response)

    with patch("openai.resources.chat.completions.AsyncCompletions.create", mock_chat_create), \
         patch("openai.resources.AsyncModerations.create", mock_mod_create):

        chat_payload = {"message": "Explain employee clearance.", "include_context": False}
        r = await async_client.post(
            "/chat",
            json=chat_payload,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["response"] == "Yes, standard clearance policies apply."
        assert "input_validator" in data["layers_fired"]


@pytest.mark.asyncio
async def test_document_ingestion_rbac(
    async_client: AsyncClient,
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """Verify document upload, list, and delete enforce correct roles."""
    # 1. Login as standard user
    std_login = await async_client.post(
        "/auth/login",
        json={"username": "standarduser", "password": "userpass123"},
    )
    std_token = std_login.json()["access_token"]

    # 2. Verify standard user cannot upload
    files = {"file": ("test.txt", b"Clearance guidelines document", "text/plain")}
    data = {"classification_level": "public", "source": "internal_docs"}
    r_std_upload = await async_client.post(
        "/documents",
        files=files,
        data=data,
        headers={"Authorization": f"Bearer {std_token}"},
    )
    assert r_std_upload.status_code == 403  # Forbidden

    # 3. Login as power user and upload
    pwr_login = await async_client.post(
        "/auth/login",
        json={"username": "poweruser", "password": "powerpass123"},
    )
    pwr_token = pwr_login.json()["access_token"]

    mock_emb_data = MagicMock(embedding=[0.1, 0.2, 0.3])
    mock_emb_resp = MagicMock(data=[mock_emb_data])
    mock_emb_create = AsyncMock(return_value=mock_emb_resp)

    mock_mod_result = MagicMock(flagged=False)
    mock_mod_response = MagicMock(results=[mock_mod_result])
    mock_mod_create = AsyncMock(return_value=mock_mod_response)

    with patch("openai.resources.embeddings.AsyncEmbeddings.create", mock_emb_create), \
         patch("openai.resources.AsyncModerations.create", mock_mod_create), \
         patch("magic.from_buffer", return_value="text/plain"):

        # Re-seek or use fresh buffer bytes
        files = {"file": ("test.txt", b"Clearance guidelines document content", "text/plain")}
        r_pwr_upload = await async_client.post(
            "/documents",
            files=files,
            data=data,
            headers={"Authorization": f"Bearer {pwr_token}"},
        )
        assert r_pwr_upload.status_code == 201
        upload_data = r_pwr_upload.json()
        doc_id = upload_data["document_id"]
        assert upload_data["filename"] == "test.txt"

        # 4. List documents (accessible to standard user)
        r_list = await async_client.get(
            "/documents",
            headers={"Authorization": f"Bearer {std_token}"},
        )
        assert r_list.status_code == 200
        list_data = r_list.json()
        assert list_data["total"] >= 1
        assert any(d["id"] == doc_id for d in list_data["documents"])

        # 5. Delete document (forbidden for power user)
        r_pwr_del = await async_client.delete(
            f"/documents/{doc_id}",
            headers={"Authorization": f"Bearer {pwr_token}"},
        )
        assert r_pwr_del.status_code == 403

        # 6. Delete document (allowed for admin)
        adm_login = await async_client.post(
            "/auth/login",
            json={"username": "admin", "password": "adminpass123"},
        )
        adm_token = adm_login.json()["access_token"]

        r_adm_del = await async_client.delete(
            f"/documents/{doc_id}",
            headers={"Authorization": f"Bearer {adm_token}"},
        )
        assert r_adm_del.status_code == 200
        assert r_adm_del.json()["document_id"] == doc_id


@pytest.mark.asyncio
async def test_admin_operation_endpoints(
    async_client: AsyncClient,
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """Test administrative routes for approvals, usages, and logs."""
    # Login as admin
    adm_login = await async_client.post(
        "/auth/login",
        json={"username": "admin", "password": "adminpass123"},
    )
    adm_token = adm_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {adm_token}"}

    # 1. Verify GET /admin/usage
    r_usage = await async_client.get("/admin/usage", headers=headers)
    assert r_usage.status_code == 200
    usage_list = r_usage.json()
    assert len(usage_list) > 0
    assert any(u["user_id"] == "standarduser" for u in usage_list)

    # 2. Verify GET /admin/audit
    r_audit = await async_client.get("/admin/audit", headers=headers)
    assert r_audit.status_code == 200
    audit_data = r_audit.json()
    assert "events" in audit_data

    # 3. Verify POST /admin/approve/{token}
    # Manually store a pending token in fake Redis
    token = "test_gated_token_123"
    redis_key = f"human_gate:token:{token}"
    token_payload = {
        "user_id": "standarduser",
        "action_category": "data_deletion",
        "status": "pending",
        "created_at": "2026-05-28T13:30:00Z",
    }
    await mock_redis.setex(redis_key, 3600, json.dumps(token_payload))

    # Approve the action
    r_app = await async_client.post(
        f"/admin/approve/{token}",
        json={"decision": "approve"},
        headers=headers,
    )
    assert r_app.status_code == 200
    app_data = r_app.json()
    assert app_data["status"] == "approved"
    assert app_data["token"] == token
    assert app_data["action"] == "data_deletion"

    # Confirm key is deleted
    assert await mock_redis.exists(redis_key) == 0
