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
