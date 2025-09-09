# FastAPI + PostgreSQL Library App Backend

A starter project for building RESTful APIs using [FastAPI](https://fastapi.tiangolo.com/) and [PostgreSQL](https://www.postgresql.org/).

## Features

- FastAPI for high-performance APIs
- PostgreSQL database integration

### Upcoming Features

- SQLAlchemy ORM
- User Authentication
- Logging
- Error Handling
- Caching
- Docker

### App Structure

```
fastapi-postgres/
├── .gitattributes
├── .gitignore
├── README.md
└── app/
    ├── __init__.py
    ├── main.py
    ├── test_main.py
    ├── mocks/
    └── src/
        ├── routes/
        │   ├── __init__.py
        │   ├── items.py
        │   └── users.py
        └── schema/
            ├── __init__.py
            ├── items.py
            └── users.py
```

## Getting Started

### Prerequisites

- Python 3.8+
- PostgreSQL

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/fastapi-postgres.git
   cd fastapi-postgres
   ```

2. Create a virtual environment using `pyenv` and activate it:

   ```bash
   pyenv install 3.8.18  # or your preferred Python version
   pyenv virtualenv 3.8.18 fastapi-postgres-env
   pyenv activate fastapi-postgres-env
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables (see `.env.example`).

5. Run database migrations (if applicable).

### Running the App

```bash
uvicorn app.main:app --reload
```

The API will be available at [http://localhost:8000](http://localhost:8000).

### Using Docker

```bash
docker-compose up --build
```

## License

This project is licensed under the MIT License.
