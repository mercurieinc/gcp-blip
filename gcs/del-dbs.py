import os
import requests
from auth import getAccessToken

auth_header = {
    'Authorization': f'Bearer {getAccessToken()}'
}

# List of DBs you want to delete
dbs = []

for db in dbs:
    print(requests.delete(
        f"https://www.googleapis.com/sql/v1beta4/projects/mercuriemart/instances/titandb/databases/{db}",
        headers=auth_header,
    ).status_code)
