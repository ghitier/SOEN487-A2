import os


class GlobalConfig(object):
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevConfig(GlobalConfig):
    SIGNING_KEY_PATH = os.path.join(os.path.dirname(__file__), "keys/demo-key.dev.pem")
    SQLALCHEMY_DATABASE_URI = r"sqlite:///demo.dev.sqlite"
    DEBUG = True


class TestConfig(GlobalConfig):
    SIGNING_KEY_PATH = os.path.join(os.path.dirname(__file__), "keys/demo-key.test.pem")
    SQLALCHEMY_DATABASE_URI = r"sqlite:///demo.test.sqlite"


class ProdConfig(GlobalConfig):
    SIGNING_KEY_PATH = os.path.join(os.path.dirname(__file__), "keys/demo-key.pem")
    SQLALCHEMY_DATABASE_URI = r"sqlite:///demo.sqlite"
