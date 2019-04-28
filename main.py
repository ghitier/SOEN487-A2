from flask import Flask, request, jsonify
from conf import DevConfig, TestConfig, ProdConfig
from exceptions import ApiError
from key import load_key, get_signing_key
from jwt_helper import create_signed_token
from datetime import timedelta
from argon2 import PasswordHasher
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)

if app.config['TESTING']:
    app.config.from_object(TestConfig)
elif app.config['ENV'] == 'development':
    app.config.from_object(DevConfig)
elif app.config['ENV'] == 'production':
    app.config.from_object(ProdConfig)

ph = PasswordHasher()
load_key(app.config['SIGNING_KEY_PATH'])

from models import db, User


@app.route('/')
def info():
    return jsonify({'msg': 'Authentication micro-service with Flask and JWT'})


@app.route('/public-key')
def public_key():
    return jsonify({'key': get_signing_key().export_public()})


@app.route('/auth/login', methods=['POST'])
def login():
    # Verify the request
    if not request.is_json:
        raise ApiError(400, 'Bad Request: no JSON data.')
    r = request.get_json()
    if ('email' not in r) or ('password' not in r):
        raise ApiError(400, 'Bad Request: \'email\' and \'password\' fields needed.')

    # Get the user by email
    user = User.query.filter_by(email=str(r['email'])).first()
    if not user:
        raise ApiError(401, 'Unauthorized: wrong email or password')
    try:
        ph.verify(user.pwdhash, str(r['password']))
    except:
        raise ApiError(401, 'Unauthorized: wrong email or password')

    # Send token to the user
    return jsonify({'token': create_signed_token(timedelta(days=1), user_id=user.id).serialize()}), 200


@app.route('/auth/register', methods=['POST'])
def register():
    # Verify the request
    if not request.is_json:
        raise ApiError(400, 'Bad Request: no JSON data.')
    r = request.get_json()
    if ('email' not in r) or ('password' not in r):
        raise ApiError(400, 'Bad Request: \'email\' and \'password\' fields needed.')

    # Create the new user
    user = User(email=str(r['email']), pwdhash=ph.hash(str(r['password'])))
    db.session.add(user)
    try:
        db.session.commit()
    except SQLAlchemyError:
        raise ApiError(500, 'Could not create the account, possibly to email is already registered.')

    # Send token to the user
    return jsonify({'token': create_signed_token(timedelta(days=1), user_id=user.id).serialize()}), 200


@app.route('/auth/refresh')
def refresh():
    raise ApiNotImplementedError()


@app.errorhandler(404)
def not_found(e):
    return jsonify({'msg': 'Not Found'}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'msg': 'Internal Server Error'}), 500


@app.errorhandler(ApiError)
def handle_api_error(error):
    return jsonify({'msg': error.msg}), error.code


if __name__ == '__main__':
    app.run()
