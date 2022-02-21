import hashlib
import secrets
import datetime
import requests
import base64
import time
from urllib.parse import urlparse, parse_qs, quote
from threading import Thread
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import sqlite3

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    client_id = None  # client_id -> client_id's string
    scopes = None     # scopes(don't forget spaces!) -> ex. "offline.access" "tweet.read users.read"
    redirect_uri = None

    code = None

    PKCE_code = None
    state = None
    start_time = None

    def do_response(self, isHEAD=False):
        class Temp:
            def __init__(self):
                self.PKCE_code = None
                self.state = None
                self.start_time = None
            
            def release(self):
                return (self.PKCE_code, self.state, self.start_time)

        temp = Temp()

        end_flag = False
        message = \
            """<!DOCTYPE HTML>
            <HTML>
            <head>
                <meta charset="utf-8">
                <title>OAuth</title>
            </head>
            <body>
            """

        mypath = urlparse(self.path)

        if mypath.path == "/redirect/oauth":
            if MyHTTPRequestHandler.start_time != None and time.monotonic() - MyHTTPRequestHandler.start_time < 60 * 15:
                message += "<h1>Error: Too Many Times</h1>"
                end_flag = True
            else:
                temp.start_time = time.monotonic()

                temp.state = secrets.token_urlsafe(64)
                temp.PKCE_code = secrets.token_urlsafe(64)
                
                url = "https://twitter.com/i/oauth2/authorize?"
                url += "response_type=code"
                url += "&client_id=" + MyHTTPRequestHandler.client_id
                url += "&redirect_uri=" + MyHTTPRequestHandler.redirect_uri
                url += "&scope=" + quote(MyHTTPRequestHandler.scopes)
                url += "&state=" + temp.state
                url += "&code_challenge=" + base64.urlsafe_b64encode(hashlib.sha256(temp.PKCE_code.encode("utf-8")).digest()).decode("utf-8").rstrip("=")
                url += "&code_challenge_method=S256"

                message += "<a href=\"" + url + "\">Login(redirect to Twitter)</a>"
        elif mypath.path == "/redirect":
            end_flag = True
            queries = parse_qs(mypath.query)
            if queries.keys() == {"state", "code"} and len(queries["state"]) == len(queries["code"]) == 1 and queries["state"][0] == temp.state:
                MyHTTPRequestHandler.code = queries["code"][0]
                message += "ok"
            else:
                message += "<h1>Error: Bad Queries</h1>"
        else:
            message += "<h1>Error: Who are you?</h1>"

        message += "</body></HTML>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(message.encode("utf-8"))))
        self.end_headers()

        if isHEAD == False:
            MyHTTPRequestHandler.PKCE_code,  \
                MyHTTPRequestHandler.state,  \
                    MyHTTPRequestHandler.start_time = temp.release()
            
            self.wfile.write(message.encode("utf-8"))
            if end_flag == True:
                th = Thread(target=self.server.shutdown)
                th.start()            

    def do_GET(self):
        self.do_response(False)

    def do_HEAD(self):
        self.do_response(True)

class Auth:
    def __init__(self, client_id, client_secret, scopes, redirect_uri, port):
        MyHTTPRequestHandler.client_id = client_id
        MyHTTPRequestHandler.scopes = scopes
        MyHTTPRequestHandler.redirect_uri = redirect_uri

        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.port = int(port)
        self.basic_header = base64.b64encode((client_id + ":" + client_secret).encode("utf-8")).decode("utf-8")
    
    def reset(self):
        db = sqlite3.connect("auth.db")
        cur = db.cursor()
        cur.execute("DROP TABLE IF EXISTS tokens")
        cur.close()
        db.commit()
        db.close()

    def exchange_code_for_tokens(self, code):
        access_token = None
        refresh_token = None
        expiration_date = None

        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "Authorization": "Basic " + self.basic_header}
        payload = {"code": code,
                   "grant_type": "authorization_code",
                   "redirect_uri": self.redirect_uri,
                   "code_verifier": MyHTTPRequestHandler.PKCE_code}
        r = requests.post("https://api.twitter.com/2/oauth2/token", headers=headers, data=payload)
        
        responses = r.json()
        if "expires_in" in responses.keys():
            expiration_date = responses["expires_in"]
        if "access_token" in responses.keys():
            access_token = responses["access_token"]
        if "refresh_token" in responses.keys():
            refresh_token = responses["refresh_token"]

        return (access_token, refresh_token, expiration_date)
    
    def renew_token(self, old_refresh_token):
        access_token = None
        new_refresh_token = None
        expiration_date = None

        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "Authorization": "Basic " + self.basic_header}
        payload = {"refresh_token": old_refresh_token,
                   "grant_type": "refresh_token",
                   "client_id": self.client_id}
        r = requests.post("https://api.twitter.com/2/oauth2/token", headers=headers, data=payload)
        
        responses = r.json()
        if "expires_in" in responses.keys():
            expiration_date = responses["expires_in"]
        if "access_token" in responses.keys():
            access_token = responses["access_token"]
        if "refresh_token" in responses.keys():
            new_refresh_token = responses["refresh_token"]

        return (access_token, new_refresh_token, expiration_date)

    def get_tokens(self):
        db = sqlite3.connect("auth.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cur = db.cursor()

        # テーブルの存在確認をして、存在しなければ認可プロセスを開始
        # 存在していれば期限を確認して切れていればリフレッシュトークンがあるかを確認して更新できるか試行
        # だめなら認可プロセスを開始
        cur.execute("""SELECT COUNT(*) FROM sqlite_master
                       WHERE TYPE ='table' AND name='tokens' """)
        
        r = cur.fetchone()[0]
        if r == 0:
            print("table not exsists. start get_token process.")
            return self.auth()
        elif r != 1:
            print("unexpected error: too many tables")
        else:
            cur.execute("""SELECT access_token, refresh_token, expiration_date FROM tokens""")
            r = cur.fetchall()
            if len(r) != 1:
                print("too many values in table 'tokens'")
            else:
                tokens = r[0]
                
                # 有効期限を過ぎていれば
                if tokens[2] < datetime.datetime.now():
                    if tokens[1] != None:
                        access_token, refresh_token, expiration_date = self.renew_token(tokens[1])
                        print("renew tokens")
                        self.save_tokens(access_token, refresh_token, expiration_date)
                        return access_token
                    else:
                        print("Not found : Refresh_token")
                        return None

                # 過ぎていなければ
                else:
                    return tokens[0]

    def save_tokens(self, access_token, refresh_token, expiration_date):
        db = sqlite3.connect("auth.db")
        cur = db.cursor()

        cur.execute("""CREATE TABLE IF NOT EXISTS tokens
                       (access_token text NOT NULL,
                        refresh_token text,
                        expiration_date timestamp NOT NULL)""")
        
        cur.execute("""DELETE FROM tokens""")
        
        cur.execute("""INSERT INTO tokens(access_token, refresh_token, expiration_date)
                       VALUES (?, ?, ?)""", (access_token, refresh_token, expiration_date))
        
        db.commit()
        db.close()

    def auth(self):
        server_address = ("", self.port)
        httpd = ThreadingHTTPServer(server_address, MyHTTPRequestHandler)
        httpd.serve_forever()

        code = MyHTTPRequestHandler.code
        access_token = None

        access_token, refresh_token, expired = self.exchange_code_for_tokens(code)
        if access_token != None:
            expiration_date = datetime.datetime.now() + datetime.timedelta(seconds=expired)
            self.save_tokens(access_token, refresh_token, expiration_date)
        else:
            print("failed: can't get access_token")
        
        return access_token
        