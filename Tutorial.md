# Authentication microservice with Flask and JWT 🔒
*In the context of or group project for SOEN487, I created a microservice to handle user authentication. I will teach you how build a microservice like mine.*

A prerequisite for this tutorial will be that you already are proficient with python3, if not you can learn from the [official python documentation](https://docs.python.org/3/tutorial/).

## 1. Our API should
- Enable a user to **register** an account.
- Enable a user to **login** using his email and password.
- Return an **access token** to the client so that he may authenticate to our other microservices without using credentials.

## 2. Basic Flask setup
Lets start by creating the file `main.py` at the root of our project folder.

You should start with this template code to get you started:
```python
from flask import Flask, jsonify

app = Flask(__name__) # Instantiates the flask app


# The `app.route` decorator makes the function below execute when the route '/' is called
@app.route('/')
def info():
    return jsonify({"msg": "Authentication microservice with Flask and JWT"})


if __name__ == '__main__':
    app.run() # Runs flask if you execute this file directly

```


## 3. Database
We will need to store the user accounts in a database. For this tutorial we will use **SQLite** as it is easy to use with flask and won't require you to install any additional software onto your computer to run the database.


To abstract the database operations we will use the  `flask-sqlalchemy` module which provides an **ORM** for SQLite.

> **ORM** (Object Relational Mapping):
> Creates an interface between object oriented applications and other incompatible type systems (like relational databases).
> Creates sort of a virtual object database.

In ORMs we need to create a **Model** for each entity we want to store. So lets create a file at the root of the project folder called `models.py` and start adding the models.

```python
from main import app # Flask app
from flask_sqlalchemy import SQLAlchemy # ORM


db = SQLAlchemy(app) # Instantiates ORM


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, nullable=False, unique=True)
    pwdhash = db.Column(db.Text, nullable=False)

db.create_all() # Initializes the ORM (based on the models)
```
> To create a model: make a class that **inherits from `db.Model`**.
>
> `db.Column`: will create a **column in the database**, takes as 1st argument the data type of that column, takes as named arguments some other options further defining that column.
>

Unfortunately the SQLAlchemy still needs to know where to create/read the database file from. Lets see how to load that from a config file in the next step.

## 4. Loading a config
As you probably know hard coding things (like database paths) is a bit dirty, luckily I'm gonna show you how you can neatly read the flask app configuration form a python file.

Lets start by creating the file `conf.py` at the root of the project.
```python
class GlobalConfig(object):
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevConfig(GlobalConfig):
    SQLALCHEMY_DATABASE_URI = r"sqlite:///demo.dev.sqlite"


class TestConfig(GlobalConfig):
    SQLALCHEMY_DATABASE_URI = r"sqlite:///demo.test.sqlite"


class ProdConfig(GlobalConfig):
    SQLALCHEMY_DATABASE_URI = r"sqlite:///demo.sqlite"
```
Those are different configurations we can load whether we are running dev, prod or tests. They currently specify where the SQLite database will reside.

Now lets add some more code to `main.py`:

First the imports
```python
from conf import DevConfig, TestConfig, ProdConfig
```

Then some code after `app = Flask(__name__)`
```python
if app.config['TESTING']:
    app.config.from_object(TestConfig)
elif app.config['ENV'] == 'development':
    app.config.from_object(DevConfig)
elif app.config['ENV'] == 'production':
    app.config.from_object(ProdConfig)
```

## 5. Exception handling
In order to handle exceptions more easily with flask, lets create some custom python Exceptions. First create a `exceptions.py` file.

```python
class ApiError(Exception):
    def __init__(self, code, msg=""):
        self.code = code
        self.msg = msg
```
Now we can define an API error with a status code and a message. If some api errors occur frequently we also could create some predefined ApiErrors by making a new Exception class inheriting from ApiError and then call the inherited constructor with some predefined parameters:
```python
class ApiNotImplementedError(ApiError):
    def __init__(self):
        super().__init__(501, "Not Implemented")
``` 

Secondly at the end of `main.py` just **before** `if __name__ == '__main__':` we have to add:
```python
@app.errorhandler(404)
def not_found(e):
    return jsonify({'msg': 'Not Found'}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'msg': 'Internal Server Error'}), 500


@app.errorhandler(ApiError)
def handle_api_error(error):
    return jsonify({'msg': error.msg}), error.code
```
The first handlers give a JSON response in case flask encounters a *route not found* or some sort of non-catched Exception. The handler for ApiError will make a response from *ApiError* whenever this Exceptions is raised in a route.

> The exceptions are very useful to raise comprehensive errors from within our code that can easily be transformed into an HTTP response.

## 6. Tokens

### Introduction to JWT
As said earlier our objective is to return a **JWT** whenever the user logs in or registers. In order to create JWTs we will use the `jwcrypto` library.

> **JWT** (JSON Web Token)
>
> JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties. This information can be verified and trusted because it is digitally signed.
> 
> In its compact form, JSON Web Tokens consist of three parts separated by dots (.), which are:
> - Header
> - Payload
> - Signature
> 
> Therefore, a JWT typically looks like the following: `xxxxx.yyyyy.zzzzz`
>
> [Read more on jwt.io](https://jwt.io/introduction/)

As we want signed tokens we need some sort of secret key to do the signature. Most generally developers tend to use the HMAC256 signing algorithm which does the signing and verification with the same secret key.

Since we will potentially create many microservices we would rather use an asymmetric cryptography method like **the RSA256 algorithm** which relies on an a **private/public keypair**.

We will use the **private key** in order to **sign** the token. We will keep this key on the server which runs the authentication service (and keep it protected).

> To generate such an RSA (private) key on Linux or MacOS: `openssl genrsa -out "keyname.pem" 2048`

We will use the **public key** in order to **verify** tokens. This key is originally derived from the private key and will be shared with everyone.

This means other services will easily be able to obtain the public key (by calling a public route in our case) and thus to verify tokens.


### Loading the signing key
Lets start by making the code to read the RSA key file, lets create the file `key.py` in the root folder of the project:
```python
from jwcrypto import jwk


def load_key(key_path: str):
    global key
    with open(key_path, mode="rb") as key_file:
        # Create JWK (JSON Web Key) from file
        key = jwk.JWK.from_pem(key_file.read())


def get_signing_key():
    return key
```

In `main.py` we can now import `load_key` and call it just after the app config, such that it will be called whenever the service starts. You could also create a new setting like `SIGNING_KEY_PATH` in `conf.py` that you may then pass to `load_key`.

As we said before we need to share the public key so other services can verify the signature of our token. So lets expose the key by importing `signing_key` and adding a new route in `main.py`:
```python
@app.route('/public-key')
def public_key():
    return jsonify({'key': get_signing_key().export_public()})
```

> **Note:** we call `.export_public()` on the key, which returns a **derived public key** of the *private* signing key (as a JWK).

### Generating JWT
Lets start by creating some helpers to create JWTs:

```python
import pytz
from jwcrypto import jwt
from datetime import datetime, timedelta
from key import get_signing_key


def create_claims(ttl: timedelta, **claims):
    now = datetime.now(tz=pytz.utc)  # It's good to have timezone info
    return {
        "iss": "Demo App",  # Token Issuer
        "exp": int((now + ttl).timestamp()),  # Time at which the token expires
        "iat": int(now.timestamp()),  # Time at which the token was issued
        "ttl": ttl.total_seconds(),  # Time To Live in seconds
        **claims,  # Add the other claims
    }


def create_signed_token(ttl: timedelta, **claims):
    token = jwt.JWT(header={"alg": "RS256", "typ": "JWT"}, claims=create_claims(ttl, **claims))  # Create
    token.make_signed_token(get_signing_key())  # Sign
    return token
```


## 7. User

Now we'll want to make the registration and login. We want the user to authenticate with his email and password. Obviously we want to **hash this password** before storing it into our database (pwdhash field in User).

One common mistake would be to use a hash function like sha512, but think again! This hash function is very fast to execute, we want **something slower**. In this example we will use the **argon2 id** hashing algorithm, you can read more about it [here](https://github.com/P-H-C/phc-winner-argon2).

We will have to install the `argon2-cffi` module in order to use the hash function. Lets create an instance `ph = PasswordHasher()` in `main.py`.

### Logging in
Lets make a route for the user to login (in `main.py`):
```python
@app.route('/login', methods=['POST'])
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
```
### Registering an account
Lets make a route for the user to register (in `main.py`):
```python
@app.route('/register', methods=['POST'])
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
```

> **Note:** the request verification is the same for login and register and thus could probably be taken apart and used for both.

## 8. Going Further 💪🏆

**Congratulations** the service should be fully functional now, but we certainly
still can make improvements. Those are features that although present in my final project I had to strip out for this tutorial. Luckily I'm briefly gonna talk about those here.

### Refresh Tokens
The biggest part I had to take out are refresh tokens. Unlike JWT tokens those do not have a payload. They could be simple sha256 hashes or UUIDs. Unlike the JWT access tokens, we want to store the refresh tokens in the database (they get associated with a user).

*But why do we need them ?* may you ask. JWTs allow the user to access the other service without ever using a password, which means that if the token gets stolen from the user it could get used to authenticate in his place. For this reason it's generally a good idea that the **JWTs are short lived** (about a few minutes). Having to login frequently is very annoying for the user, that is where the refresh token comes in: When authenticating the user will receive an access token and a refresh token. The **refresh token will be long lived** (weeks, months, whatever) and can be used to **request a fresh access token**.

*But how does refreshing the token help with security?* may you ask. Since the refresh token is stored in the database **we can revoke the refresh token, forcing the user to log in again** to obtain a new one. Furthermore we may add a hash of the refresh token as the access tokens issuer field *(iss)*. This might allow to potentially create a mechanism to revoke the actual access tokens (which is normally impossible) by having a blacklist of refresh token hashes. Although you have to be careful not to create anti-patterns when trying to implement this.


### Flask blueprints
For the tutorial we ended up putting every route in a single file. As you can imagine this will get messy very fast. To avoid this issue we can use flask blueprints.

For this you simply create other files in which you start by instantiating the Blueprint class from Flask. Instead of doing `@app.route(...)` you now do `@your_bp_instance.route(...)`.

In your main file you can then import that blueprint instance, just do `app.register_blueprint(the_imported_bp_instance)`.


### Authorizing (from the perspective of another service)
At the start of the service you will want to obtain the public key from the authentication service (the one in the tutorial), you can import the JWK (JSON Web Key) directly from the requests response.


It may be interesting for you to do the authorization in some sort of decorator functions in order to make it easy to do for multiple routes.

To authorize a user with the token:
- Read the token from the HTTP requests `Authorization` header
- Check that the JWT format is valid
- Check that the JWT header is as expected (RSA256 algorithm)
- Verify the signature with the public key obtained at startup
- Check that the token is not expired
- Obtain any other payload fields your interested in (user_id, permissions, etc)

---

![Thats all folks](https://media.giphy.com/media/5IT69msgpaOcg/giphy.gif)

---
**Author:** Guillaume HITIER (*id: 40102556*)