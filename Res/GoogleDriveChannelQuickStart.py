from __future__ import print_function
import os.path
from google_auth_oauthlib.flow import InstalledAppFlow
from pprint import pprint

# Adapted from 
# https://developers.google.com/drive/api/v3/quickstart/python

# Steps
# 1 - Login to Google Account
# 2 - Visit the above link and click the 'Enable the Drive API' button
# 3 - Download the credentials.json file and place it in the same dir as this script
# 4 - Execute this script and accept the access requests in your default browser
# 5 - Copy the _client_id, _client_secret and _refresh_token from the dict output
# 6 - Use those values for C3

SCOPES = ['https://www.googleapis.com/auth/drive']

def main():
    
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES)
    creds = flow.run_local_server(port=0)
    pprint(creds.__dict__)

if __name__ == '__main__':
    main()