from main import app  # Flask app
from flask_sqlalchemy import SQLAlchemy  # ORM


db = SQLAlchemy(app)  # Instantiates ORM


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, nullable=False, unique=True)
    pwdhash = db.Column(db.Text, nullable=False)


db.create_all()  # Initializes the ORM (based on the models)

