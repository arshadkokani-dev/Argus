import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base, get_db
from app.main import app

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def get_auth_headers(email: str) -> dict[str, str]:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "StrongPassword123!"},
    )
    res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassword123!"},
    )
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_target_crud_plan_limits_and_isolation():
    user_a = get_auth_headers("alice@argussec.io")
    user_b = get_auth_headers("bob@argussec.io")

    # 1. Create target with full URL -> normalized to root domain
    create_res = client.post(
        "/api/v1/targets",
        json={"domain": "https://myportfolio.in"},
        headers=user_a,
    )
    assert create_res.status_code == 201
    target = create_res.json()
    assert target["domain"] == "myportfolio.in"
    assert target["base_url"] == "https://myportfolio.in"
    assert target["is_verified"] is False
    assert target["verification_token"].startswith("argus-verify=")

    # 2. FREE plan limit blocks 2nd website -> 403
    second_res = client.post(
        "/api/v1/targets",
        json={"domain": "secondsite.com"},
        headers=user_a,
    )
    assert second_res.status_code == 403

    # 3. User B cannot delete User A's target -> 404
    idor_del = client.delete(f"/api/v1/targets/{target['id']}", headers=user_b)
    assert idor_del.status_code == 404

    # 4. User A can delete their own target -> 204
    own_del = client.delete(f"/api/v1/targets/{target['id']}", headers=user_a)
    assert own_del.status_code == 204