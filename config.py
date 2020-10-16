from os import path, getenv

from pymongo import MongoClient

basedir = path.abspath(path.dirname(__file__))


class Config:
    SECRET_KEY = getenv('SECRET_KEY')
    JWT_SECRET_KEY = getenv('JWT_SECRET_KEY')

    SESSION_TYPE = getenv('SESSION_TYPE')
    SESSION_PERMANENT = getenv('SESSION_PERMANENT')
    PERMANENT_SESSION_LIFETIME = int(getenv('PERMANENT_SESSION_LIFETIME'))

    GOOGLE_CLIENT_ID = getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = getenv('GOOGLE_CLIENT_SECRET')


class LocalConfig(Config):
    FLASK_ENV = 'local'
    DEBUG = True
    TESTING = True
    DEV_MONGODB_URI = getenv('DEV_MONGODB_URI')
    DEV_MONGODB_DB = getenv('DEV_MONGODB_DB')
    SESSION_MONGODB = MongoClient(DEV_MONGODB_URI)
    SESSION_MONGODB_DB = DEV_MONGODB_DB
    OAUTHLIB_INSECURE_TRANSPORT = 1
