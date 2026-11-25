import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.agent.models import AgentRun, AgentStep, ActionProposal
from app.database.session import Base
from app.models.entities import Incident, AnalystAccount


@pytest.fixture
def db_pair():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    with factory() as db:
        yield db, factory
    engine.dispose()
