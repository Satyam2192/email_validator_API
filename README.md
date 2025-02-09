# Email Validation API

## Setup

```bash
# 1. Create virtual environment
python3 -m venv .venv

# Activate on Windows
.venv\Scripts\activate

# Activate on macOS/Linux
source .venv/bin/activate


# 2. Install dependencies:

pip install --upgrade pip
pip install -r requirements.txt

# 3. Run the FastAPI application:

uvicorn main:app --reload

# 4. Run the tests using pytest:
pytest email_validator_API/tests/


```