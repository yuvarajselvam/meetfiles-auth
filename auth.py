import os
import uuid

import config
import inspect
from enum import Enum
from datetime import datetime

import msal

from flask_session import Session
from flask_pymongo import PyMongo
from flask_login import LoginManager, login_user
from flask import Flask, session, redirect, request

from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import InvalidGrantError

import validation

uri = os.getenv("DEV_MONGODB_URI")
database = os.getenv("DEV_MONGODB_DB")

app = Flask(__name__)
app.config.from_object(config.LocalConfig)

Session(app)

login_manager = LoginManager(app)
db = PyMongo(app, uri, connect=True).cx[database]


# Models

class EntityBase:
    _collection = None
    _required_fields = []

    def __init__(self, *args, **kwargs):
        [setattr(self, k, v) for arg in args for k, v in arg.items() if hasattr(self, k)]
        [setattr(self, k, v) for k, v in kwargs.items() if hasattr(self, k)]

    def validate(self):
        for field in self._required_fields:
            if not getattr(self, field):
                formatted_field_name = ''.join(map(lambda x: x if x.islower() else " " + x, field)).title()
                raise KeyError(f"{formatted_field_name} is mandatory.")

    def json(self):
        attributes = inspect.getmembers(self, lambda a: not (inspect.isroutine(a)))
        return dict([(a, v) for a, v in attributes if (not a.startswith('_')) and a[0].islower() and v])


class Entity(EntityBase):
    _resource_prefix = ''

    _id = \
        _updatedAt = \
        _createdAt = None

    def save(self, validate=True):
        if validate:
            self.validate()

        if not self.id:
            self.id = uuid.uuid4().hex

        if not self.createdAt:
            self._createdAt = datetime.utcnow()

        self._updatedAt = datetime.utcnow()
        db[self._collection].update_one({"id": self.id}, {"$set": self.json()}, upsert=True)

    @classmethod
    def find_one(cls, query=None):
        document = db[cls._collection].find_one(query)
        if not document:
            return
        return cls(document)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        validation.check_instance_type("id", value, str)
        self._id = self._resource_prefix + value if not value.startswith(self._resource_prefix) else value

    @property
    def createdAt(self):
        return self._createdAt

    @createdAt.setter
    def createdAt(self, value):
        self._createdAt = value

    @property
    def updatedAt(self):
        return self._updatedAt

    @updatedAt.setter
    def updatedAt(self, value):
        self._updatedAt = value


class User(Entity):
    _collection = 'users'
    _resource_prefix = 'USR'
    _required_fields = ["primaryAccount"]
    _accounts = \
        _primary_account = None

    def add_account(self, account, account_type):
        self.Account.Type(account_type.lower())  # For validating account type
        self._accounts = dict() if not self._accounts else self._accounts
        self.accounts[account_type.lower()] = self.Google(account).json()

    # Properties

    @property
    def primaryAccount(self):
        return self._primary_account.value if self._primary_account else None

    @primaryAccount.setter
    def primaryAccount(self, value):
        self._primary_account = self.Account.Type(value.lower())

    @property
    def accounts(self):
        return self._accounts

    @accounts.setter
    def accounts(self, value):
        self._accounts = value

    # Nested classes

    class Account(EntityBase):
        _required_fields = ["email", "name"]

        _type = ''
        _name = \
            _email = \
            _image_url = None

        @property
        def name(self):
            return self._name

        @name.setter
        def name(self, value):
            display_name = "Name"
            validation.check_instance_type(display_name, value, str)
            validation.check_min_length(display_name, value, 1)
            self._name = value

        @property
        def email(self):
            return self._email

        @email.setter
        def email(self, value):
            display_name = "Email"
            validation.check_instance_type(display_name, value, str)
            validation.check_regex_match(display_name, value, validation.EMAIL_REGEX)
            self._email = value

        @property
        def imageUrl(self):
            return self._image_url

        @imageUrl.setter
        def imageUrl(self, value):
            validation.check_regex_match("Image URL", value, validation.URL_REGEX)
            self._image_url = value

        # <editor-fold desc="Account Type Enum">
        class Type(Enum):
            GOOGLE = 'google'
            AZURE = 'azure'
        # </editor-fold>

    class Google(Account):
        _refresh_token = None

        def __init__(self, *args, **kwargs):
            self._type = self.Type.GOOGLE.value.lower()
            super().__init__(*args, **kwargs)

        # Properties

        @property
        def refreshToken(self):
            return self._refresh_token

        @refreshToken.setter
        def refreshToken(self, value):
            self._refresh_token = value

    class Azure(Account):
        def __init__(self, *args, **kwargs):
            self._type = self.Type.AZURE.value.lower()
            super().__init__(*args, **kwargs)

    # Flask login - Properties

    _is_authenticated = False
    _is_active = True
    _is_anonymous = False

    def authenticate(self):
        self._is_authenticated = True

    def is_authenticated(self):
        return self._is_authenticated

    def is_active(self):
        return self._is_active

    def is_anonymous(self):
        return self._is_anonymous

    def get_id(self):
        return self.id


# Flask login - User loader

@login_manager.user_loader
def load_user(user_id):
    return User.find_one({"id": user_id})


# Google Signin Routes

# <editor-fold desc="Google OAuth Params">
google_client_id = config.Config.GOOGLE_CLIENT_ID
google_client_secret = config.Config.GOOGLE_CLIENT_SECRET
google_token_url = "https://accounts.google.com/o/oauth2/token"
google_auth_base_url = "https://accounts.google.com/o/oauth2/auth"
google_redirect_uri = os.getenv('BASE_URL') + 'signin/google/callback/'
google_scopes = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
# </editor-fold>


@app.route('/signin/google/')
def google_signin():
    google = OAuth2Session(google_client_id, scope=google_scopes, redirect_uri=google_redirect_uri)
    auth_url, state = google.authorization_url(google_auth_base_url, access_type="offline", prompt="select_account")
    session['oauth_state'] = state
    return redirect(auth_url)


@app.route('/signin/google/callback/')
def google_signin_callback():
    if 'oauth_state' not in session:
        return {"message": "Session expired."}, 440

    google = OAuth2Session(google_client_id, redirect_uri=google_redirect_uri,
                           state=session['oauth_state'])
    try:
        token = google.fetch_token(google_token_url, client_secret=google_client_secret,
                                   code=request.args['code'])
    except InvalidGrantError:
        return {"message": "Invalid Credentials."}, 401

    user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    user = User.find_one({"accounts.google.email": user_info["email"]})
    if not user:
        user_object = {
            "id": "USR" + user_info["id"],
            "primaryAccount": User.Account.Type.GOOGLE.value,
        }
        user = User(user_object)
        google_object = {
            "name": user_info["name"],
            "email": user_info["email"],
            "imageUrl": user_info.pop("picture", None),
            "phone": user_info.pop("phone", None)
        }
        user.add_account(google_object, user.primaryAccount)
        user.save()
    user.authenticate()
    login_user(user)
    session['oauth_token'] = token
    return redirect('http://localhost:3000')


# Azure Signin Routes

# <editor-fold desc="Azure OAuth Params">
azure_client_id = os.getenv('AZURE_CLIENT_ID')
azure_client_secret = os.getenv('AZURE_CLIENT_SECRET')
azure_redirect_uri = os.getenv('BASE_URL') + 'signin/azure/callback/'
azure_authority = "https://login.microsoftonline.com/common"
azure_scopes = ["User.ReadBasic.All"]
# </editor-fold>


def _build_msal_app():
    return msal.ConfidentialClientApplication(azure_client_id,
                                              client_credential=azure_client_secret,
                                              authority=azure_authority)


@app.route('/signin/azure/')
def azure_signin():
    state = str(uuid.uuid4())
    azure = _build_msal_app()
    auth_url = azure.get_authorization_request_url(azure_scopes, state=state,
                                                   redirect_uri=azure_redirect_uri)
    session['oauth_state'] = state
    return redirect(auth_url)


@app.route('/signin/azure/callback/')
def azure_signin_callback():
    if request.args.get('state') != session.get("oauth_state"):
        return {"message": "Session expired."}, 440

    if "error" in request.args or "code" not in request.args:
        return {"message": "Invalid Credentials."}, 401

    code = request.args.get('code')
    azure = _build_msal_app()
    result = azure.acquire_token_by_authorization_code(
        code, azure_scopes, redirect_uri=azure_redirect_uri)
    if "error" in result:
        return {"message": "Invalid Credentials."}, 401
    session["user"] = result.get("id_token_claims")
    accounts = azure.get_accounts()
    result = azure.acquire_token_silent(azure_scopes, account=accounts[0])
    return result


if __name__ == '__main__':
    app.run('0.0.0.0', os.getenv('PORT'))
