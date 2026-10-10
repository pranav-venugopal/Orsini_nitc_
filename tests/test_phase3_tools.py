"""Phase 3 tests: Safe tool usage and indirect prompt injection defense.

Proves:
(1) Allowed calculator call executes safely.
(2) Dangerous command 'rm -rf /' is blocked.
(3) SSRF cloud metadata IP (http://169.254.169.254/) is blocked.
(4) Unsafe URL scheme (file:///etc/passwd) is blocked.
(5) Base64-encoded dangerous command is blocked via de-obfuscated view inspection.
(6) Unlisted tool ('shell') is blocked.
(7) send_email requires explicit admin approval (approve=True).
(8) Hostile document from tests/red_team/fixtures/hostile_document.txt is blocked as indirect injection.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest
from fastapi.testclient import TestClient

import api
from app.auth import _issue_token
from app.config import settings
from tools import outbox


@pytest.fixture
def auth_tokens():
    settings.admin_username = "test-admin"
    settings.admin_password = "admin-secret-password-123!"
    settings.member_username = "test-member"
    settings.member_password = "member-secret-password-123!"

    admin_token = _issue_token("test-admin", "admin").access_token
    member_token = _issue_token("test-member", "member").access_token
    return admin_token, member_token


@pytest.fixture
def test_client():
    return TestClient(api.app)


def test_allowed_calculator_call_works(test_client, auth_tokens):
    """Allowed calculator call executes safely with ast evaluation."""
    _, member_token = auth_tokens
    headers = {"Authorization": f"Bearer {member_token}"}

    resp = test_client.post(
        "/agent/tool",
        json={"name": "calculator", "args": {"expr": "15 * 3 + 7"}},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "executed"
    assert data["decision"] == "ALLOW"
    assert data["result"]["result"] == 52
    assert data["result"]["status"] == "success"


def test_rm_rf_tool_call_is_blocked(test_client, auth_tokens):
    """Dangerous shell payload rm -rf / is blocked by ToolCallGuard."""
    _, member_token = auth_tokens
    headers = {"Authorization": f"Bearer {member_token}"}

    resp = test_client.post(
        "/agent/tool",
        json={"name": "calculator", "args": {"expr": "rm -rf /"}},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert data["reason"] == "dangerous_tool_args"
    assert data["result"] is None


def test_ssrf_metadata_is_blocked(test_client, auth_tokens):
    """Cloud metadata IP http://169.254.169.254/ is blocked by ToolCallGuard."""
    _, member_token = auth_tokens
    headers = {"Authorization": f"Bearer {member_token}"}

    resp = test_client.post(
        "/agent/tool",
        json={"name": "fetch_url", "args": {"url": "http://169.254.169.254/latest/meta-data"}},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert "private_or_metadata_ip" in data["reason"] or "domain_not_allowed" in data["reason"]


def test_unsafe_url_scheme_is_blocked(test_client, auth_tokens):
    """Unsafe scheme file:///etc/passwd is blocked by ToolCallGuard."""
    _, member_token = auth_tokens
    headers = {"Authorization": f"Bearer {member_token}"}

    resp = test_client.post(
        "/agent/tool",
        json={"name": "fetch_url", "args": {"url": "file:///etc/passwd"}},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert data["reason"] == "unsafe_url_scheme"


def test_base64_encoded_dangerous_command_is_blocked(test_client, auth_tokens):
    """Base64-encoded dangerous command is decoded and blocked."""
    _, member_token = auth_tokens
    headers = {"Authorization": f"Bearer {member_token}"}

    encoded = base64.b64encode(b"rm -rf / --no-preserve-root").decode()
    resp = test_client.post(
        "/agent/tool",
        json={"name": "calculator", "args": {"expr": encoded}},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert "dangerous_tool_args" in data["reason"]


def test_unlisted_tool_is_blocked(test_client, auth_tokens):
    """Tool not in allowed_tools is rejected."""
    _, member_token = auth_tokens
    headers = {"Authorization": f"Bearer {member_token}"}

    resp = test_client.post(
        "/agent/tool",
        json={"name": "shell", "args": {"cmd": "ls -la"}},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert data["reason"] == "tool_not_allowed"


def test_send_email_approval_flow(test_client, auth_tokens):
    """send_email returns review_required unless explicitly approved by an admin."""
    admin_token, member_token = auth_tokens
    initial_count = len(outbox)

    # 1. Member attempt -> review_required
    resp_mem = test_client.post(
        "/agent/tool",
        json={
            "name": "send_email",
            "args": {"to": "partner@example.com", "subject": "Contract", "body": "Please sign."},
            "approve": True,
        },
        headers={"Authorization": f"Bearer {member_token}"},
    )
    assert resp_mem.status_code == 200
    assert resp_mem.json()["status"] == "review_required"
    assert len(outbox) == initial_count

    # 2. Admin attempt without approve=True -> review_required
    resp_adm_no_app = test_client.post(
        "/agent/tool",
        json={
            "name": "send_email",
            "args": {"to": "partner@example.com", "subject": "Contract", "body": "Please sign."},
            "approve": False,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_adm_no_app.status_code == 200
    assert resp_adm_no_app.json()["status"] == "review_required"
    assert len(outbox) == initial_count

    # 3. Admin attempt with approve=True -> executed
    resp_adm_app = test_client.post(
        "/agent/tool",
        json={
            "name": "send_email",
            "args": {"to": "partner@example.com", "subject": "Contract", "body": "Please sign."},
            "approve": True,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_adm_app.status_code == 200
    assert resp_adm_app.json()["status"] == "executed"
    assert len(outbox) == initial_count + 1


def test_hostile_document_blocked_as_indirect_injection(test_client, auth_tokens):
    """Hostile document fixture passed as context is blocked as indirect injection."""
    _, member_token = auth_tokens
    headers = {"Authorization": f"Bearer {member_token}"}

    fixture_path = os.path.join(
        os.path.dirname(__file__), "red_team", "fixtures", "hostile_document.txt"
    )
    with open(fixture_path, "r", encoding="utf-8") as f:
        hostile_text = f.read()

    resp = test_client.post(
        "/chat",
        json={
            "message": "Please summarize this document.",
            "context": [hostile_text],
        },
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    # Must be blocked as indirect injection and document reported dropped
    assert data["status"] == "blocked"
    assert data["action"] == "blocked_context"
    assert "injection" in data["input_check"]["categories"]
    assert len(data["dropped_context"]) >= 1
