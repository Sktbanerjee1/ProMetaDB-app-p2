import secrets
from src import app

app.config.update(
    SECRET_KEY=secrets.token_hex(10),
    SQLALCHEMY_DATABASE_URI='sqlite:///ProMetaDB.db'
)