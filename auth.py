import time
import json
import jwt
import requests
import httplib2

# Project ID for this request.
project = ''

# The name of the zone for this request.
zone = ''

# Permissions to request for Access Token
scopes = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/analytics.edit"
# Set how long this token will be valid in seconds
expires_in = 3600  # Expires in 1 hour


def load_private_key(json_cred):
    ''' Return the private key from the json credentials '''

    return json_cred['private_key']


def create_signed_jwt(pkey, pkey_id, email, scope):
    '''
    Create a Signed JWT from a service account Json credentials file
    This Signed JWT will later be exchanged for an Access Token
    '''

    # Google Endpoint for creating OAuth 2.0 Access Tokens from Signed-JWT
    auth_url = "https://www.googleapis.com/oauth2/v4/token"

    issued = int(time.time())
    expires = issued + expires_in  # expires_in is in seconds

    # Note: this token expires and cannot be refreshed. The token must be recreated

    # JWT Headers
    additional_headers = {
        'kid': pkey_id,
        "alg": "RS256",
        "typ": "JWT"  # Google uses SHA256withRSA
    }

    # JWT Payload
    payload = {
        "iss": email,		# Issuer claim
        "sub": email,		# Issuer claim
        "aud": auth_url,  # Audience claim
        "iat": issued,		# Issued At claim
        "exp": expires,		# Expire time
        "scope": scope		# Permissions
    }

    # Encode the headers and payload and sign creating a Signed JWT (JWS)
    sig = jwt.encode(payload, pkey, algorithm="RS256",
                     headers=additional_headers)

    return sig


def exchangeJwtForAccessToken(signed_jwt):
    '''
    This function takes a Signed JWT and exchanges it for a Google OAuth Access Token
    '''

    auth_url = "https://www.googleapis.com/oauth2/v4/token"

    params = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt
    }

    r = requests.post(auth_url, data=params)

    if r.ok:
        return(r.json()['access_token'], '')

    return None, r.text


def getAccessToken(request):
    # Contents of JSON Service Account
    cred = {
    }

    private_key = load_private_key(cred)

    s_jwt = create_signed_jwt(
        private_key,
        cred['private_key_id'],
        cred['client_email'],
        scopes)

    token, err = exchangeJwtForAccessToken(s_jwt)

    return token
