# Development Guide

## Setting Up Local Development

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- VS Code (recommended)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/sentineliq.git
cd sentineliq

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r backend/requirements.txt

# Install dev dependencies
pip install pytest pytest-asyncio httpx black isort mypy

# Copy environment file
cp .env.example .env
```

### Running Locally

**Option 1: Full Docker Stack**
```bash
docker-compose up --build
```

**Option 2: Hybrid (DB in Docker, API locally)**
```bash
# Start infrastructure only
docker-compose up postgres redis minio -d

# Run API locally
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Project Structure

```
backend/
├── app/
│   ├── main.py           # FastAPI application entry
│   ├── config.py         # Configuration settings
│   ├── models.py         # SQLAlchemy models
│   ├── dependencies.py   # Dependency injection
│   ├── api/              # API routers (legacy)
│   ├── routes/           # HTTP endpoint handlers
│   ├── services/         # Business logic layer
│   ├── core/             # Infrastructure utilities
│   ├── schemas/          # Pydantic models
│   ├── middleware/       # Request middleware
│   └── templates/        # Email templates
├── rules/                # Fraud detection rules
├── tests/                # Test suite
├── Dockerfile
└── requirements.txt
```

## Code Style

We follow PEP 8 with these tools:

```bash
# Format code
black backend/

# Sort imports
isort backend/

# Type checking
mypy backend/app
```

## Testing

```bash
# Run all tests
pytest backend/tests/ -v

# Run specific test file
pytest backend/tests/test_milestone_1_2.py -v

# Run with coverage
pytest backend/tests/ --cov=app --cov-report=html
```

## Adding New Features

### 1. Adding a New Endpoint

```python
# backend/app/routes/my_feature.py
from fastapi import APIRouter, Depends
from app.dependencies import get_current_user

router = APIRouter(prefix="/my-feature", tags=["my-feature"])

@router.get("/")
def get_items(user = Depends(get_current_user)):
    return {"items": []}
```

```python
# backend/app/main.py
from app.routes import my_feature
app.include_router(my_feature.router)
```

### 2. Adding a New Model

```python
# backend/app/models.py
class MyModel(Base):
    __tablename__ = "my_models"
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
```

### 3. Adding a New Fraud Rule

Edit `backend/rules/fraud_rules.yaml`:

```yaml
rules:
  hard_rules:
    - id: "my_new_rule"
      name: "My New Rule"
      enabled: true
      risk_score: 0.9
      action: "block"
      conditions:
        some_field: { eq: "value" }
```

## Debugging

### VS Code Launch Config

```json
{
  "name": "FastAPI Debug",
  "type": "python",
  "request": "launch",
  "module": "uvicorn",
  "args": ["app.main:app", "--reload"],
  "cwd": "${workspaceFolder}/backend",
  "env": {
    "PYTHONPATH": "${workspaceFolder}/backend"
  }
}
```

## Common Issues

### Database Connection Error
```bash
# Ensure PostgreSQL is running
docker-compose up postgres -d
```

### Redis Connection Error
```bash
# Ensure Redis is running
docker-compose up redis -d
```

### Import Errors
```bash
# Ensure you're in the right directory
cd backend
export PYTHONPATH=$PWD
```
