# OpenMRS O3 Security Testing

Automated security tests for OpenMRS 3 with CVSS vulnerability scoring.

## Prerequisites

- Python 3.9+
- Docker (for running local OpenMRS instance)

## Setup

### 1. Clone and set up virtual environment

```bash
git clone https://github.com/openmrs/openmrs-contrib-cvss-scanning.git
cd openmrs-contrib-cvss-scanning

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Playwright browsers

```bash
playwright install chromium
```

### 4. Configure environment

```bash
cp .env.example .env
```

Edit `.env` to change the target OpenMRS instance if needed:

```
# Default targets local Docker instance
O3_BASE_URL=http://localhost/openmrs/spa

# Or target the public demo server
O3_BASE_URL=https://o3.openmrs.org/openmrs/spa
```

### 5. Start OpenMRS (local testing)

For local testing, spin up an OpenMRS 3 Docker instance:

```bash
docker compose up
```

Wait for the container to fully start (this may take a few minutes). The instance will be available at http://localhost/openmrs/spa

## Running Tests

Run all security tests:

```bash
pytest tests/ -v
```

Run specific test categories:

```bash
# Authentication tests only
pytest tests/authentication/ -v

# Session management tests only
pytest tests/session_management/ -v
```

Generate HTML report:

```bash
pytest tests/ -v --html=report.html --json-report --json-report-file=report.json
```

Generate security dashboard:

```bash
pytest tests/ -v --json-report --json-report-file=report.json | tee test_output.log
python scripts/generate_security_dashboard.py
```

## Test Structure

```
tests/
├── authentication/           # Authentication security tests
│   ├── conftest.py          # Shared fixtures and URL config
│   ├── test_01_username_enumeration.py
│   ├── test_02_credential_guessing.py
│   └── ...
└── session_management/       # Session management tests
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `O3_BASE_URL` | `http://localhost/openmrs/spa` | Base URL of the OpenMRS O3 instance |
| `CI` | - | Set automatically in CI environments for headless browser mode |
