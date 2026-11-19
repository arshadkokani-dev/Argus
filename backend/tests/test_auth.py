import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base, get_db
from app.main import app

SQLALCHEMY_TEST_DATABASE_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
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


def test_register_login_and_me_flow():
    # 1. Register new user
    reg_res = client.post(
        "/api/v1/auth/register",
        json={"email": "Dev@ArgusSec.io", "password": "StrongPassword123!"},
    )
    assert reg_res.status_code == 201
    user_data = reg_res.json()
    assert user_data["email"] == "dev@argussec.io"
    assert user_data["plan_tier"] == "FREE"
    assert "hashed_password" not in user_data

    # 2. Reject duplicate email
    dup_res = client.post(
        "/api/v1/auth/register",
        json={"email": "dev@argussec.io", "password": "AnotherPassword123!"},
    )
    assert dup_res.status_code == 400

    # 3. Reject wrong password
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"email": "dev@argussec.io", "password": "WrongPassword!"},
    )
    assert bad_login.status_code == 401

    # 4. Login with valid credentials
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "dev@argussec.io", "password": "StrongPassword123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # 5. Access protected /me route without token -> 401 or 403
    unauth_me = client.get("/api/v1/auth/me")
    assert unauth_me.status_code in (401, 403)


    # 6. Access protected /me route with invalid token -> 401
    invalid_me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert invalid_me.status_code == 401

    # 7. Access protected /me route with valid Bearer token -> 200
    auth_me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert auth_me.status_code == 200
    assert auth_me.json()["email"] == "dev@argussec.io"
