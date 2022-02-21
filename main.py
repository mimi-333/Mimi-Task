import requests
import sys
import sqlite3
from dotenv import dotenv_values

import mimi_oauth2

#load a env file(.env)
tokens = dotenv_values()
#print(config)

scopes = "tweet.read tweet.write users.read"# offline.access"
auth = mimi_oauth2.Auth(tokens["CLIENT_ID"], tokens["CLIENT_SECRET"], scopes, tokens["REDIRECT_URI"], tokens["PORT"])

if len(sys.argv) == 2 and sys.argv[1] == "--init":
    auth.reset()
    auth.get_tokens()
else:
    #payload = {"Aut": "key", }
    #r = requests.get("https://api.twitter.com/2/users//tweets", params=payload)
    #headers = {"Authorization": "Bearer " + tokens["BEARER_TOKEN"]}
    #r = requests.get("https://api.twitter.com/2/users/by?usernames=geko_gekko3", headers=headers)

    #r = requests.get("https://api.twitter.com/2/users/1353523565996326913/tweets", headers=headers)
    #print(r.text)
    # {"data":[{"id":"2484838384","text":"にゃー－ん"},{"id":"4444","text"}],
    #  "meta":{"oldest_id":"4444","newest_id":"2484838384","result_count":2,"next_token":"47u4hfhru"}}
    #print(type(r.text))
    # <class 'str'>

    token = auth.get_tokens()
    headers = {"Authorization": "Bearer " + token}
    payload = {"text": "にゃーん"}
    r = requests.post("https://api.twitter.com/2/tweets", headers=headers, json=payload)
    print(r.status_code)
    print(r.text)
