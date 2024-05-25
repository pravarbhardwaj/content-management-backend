# Backend Interview

Content Management Backend is a FastAPI project which contains api for Content Management

## Setup

use package manager pip to install requirements 

```bash
pip install -r requirements.txt
```

##Run the project 

```bash
fastapi dev main.py 
```

## Migrations
Run this script after making changes in model(s)

```bash
alembic revision --autogenerate -m "Revision Name"
```

To upgrade/downgrade run - 

```bash
alembic upgrade head

alembic downgrade head
```

## Generate Secret Key
```
openssl rand -hex 32
```

## Run Interactive Shell Mode 
```
python -m asyncio -i app/app/main.py
```
