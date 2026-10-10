"""Tests for Phase 5: Tamper-evident Audit Trail and Verification.

Proves:
1. Unauthenticated requests to /security/audit/verify and /security/events/export -> 401
2. Member token requests -> 403
3. Admin requests can verify audit chain and export in json and csv format
4. Tampering detection: intentionally modifying an event hash or prev_hash causes verify to report failure and identify the broken index.
"""
import os
import sys
import sqlite3
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from api import app
from app import database, events
from app.config import settings
from app.auth import _issue_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    settings.admin_username = "test-admin"
    settings.admin_password = "admin-secret-password-123!"
    token = _issue_token("test-admin", "admin").access_token
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def member_headers():
    settings.member_username = "test-member"
    settings.member_password = "member-secret-password-123!"
    token = _issue_token("test-member", "member").access_token
    return {"Authorization": f"Bearer {token}"}


def test_audit_endpoints_require_admin(client, member_headers):
    # Unauthenticated -> 401
    assert client.get("/security/audit/verify").status_code == 401
    assert client.get("/security/events/export").status_code == 401

    # Member -> 403
    assert client.get("/security/audit/verify", headers=member_headers).status_code == 403
    assert client.get("/security/events/export", headers=member_headers).status_code == 403


def test_audit_chain_verification_and_export(client, admin_headers):
    # Log a few events
    events.log_event("req_t1", "input", "safe", [], "passed", 10)
    events.log_event("req_t2", "output", "safe", [], "passed", 15)
    events.log_event("req_t3", "input", "unsafe", ["injection"], "blocked_input", 5)

    # Verify chain
    res = client.get("/security/audit/verify", headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["verified"] is True
    assert data["broken_at_index"] is None

    # Export JSON
    res_json = client.get("/security/events/export?format=json", headers=admin_headers)
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    exported = res_json.json()
    assert isinstance(exported, list)
    assert len(exported) >= 3
    assert "prev_hash" in exported[0]
    assert "hash" in exported[0]

    # Export CSV
    res_csv = client.get("/security/events/export?format=csv", headers=admin_headers)
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    csv_text = res_csv.text
    assert "event_id,timestamp,request_id,stage" in csv_text
    assert "prev_hash,hash" in csv_text


def test_tamper_detection(client, admin_headers):
    # Log known events
    e1 = events.log_event("req_tamper_1", "input", "safe", [], "passed", 12)
    e2 = events.log_event("req_tamper_2", "output", "safe", [], "passed", 18)

    # Corrupt event e2 hash in DB directly
    with database.connection() as conn:
        with conn.cursor() if database.using_postgres() else conn as cursor:
            database.execute(cursor, "UPDATE events SET hash = 'corrupted_hash_val' WHERE event_id = ?", (e2,))

    # Verification must now fail!
    res = client.get("/security/audit/verify", headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["verified"] is False
    assert data["broken_event_id"] == e2
    assert "mismatch" in data["reason"].lower()
