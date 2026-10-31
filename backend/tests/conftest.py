"""
Test configuration: isolate all tests from the production database.

Every test that calls scan_message(), scan_url(), get_scan_history(), etc.
receives an isolated in-memory SQLite session via pytest fixtures.  No test
may write to the production scamsentry.db file.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.models.scan_record import ScanRecord  # noqa: F401 – registers the model


# --------------------------------------------------------------------------- #
#  In-memory SQLite engine shared across the entire test session              #
# --------------------------------------------------------------------------- #
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


# --------------------------------------------------------------------------- #
#  Session-scoped fixture: create tables once per pytest run                  #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all ORM tables in the in-memory DB before any test runs."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


# --------------------------------------------------------------------------- #
#  Function-scoped fixture: fresh DB session that rolls back after each test  #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def db():
    """
    Yields an isolated SQLAlchemy session backed by the in-memory test DB.
    All writes are rolled back after the test so each test starts clean.
    """
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()
