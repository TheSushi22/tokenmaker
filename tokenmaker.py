import requests
import time
import webbrowser
import json
import os

filename = "REPLACE WITH YOUR EMAIL TXT FILE"

with open(filename, 'r') as file:
    for line in file:
        email_with_password = line.strip()
        parts = email_with_password.split(':')
        if len(parts) != 2:
            continue

        email = parts[0]
        password = parts[1]

        bearer = ""
        host = "http://api.ifunny.mobi"

        def generateBasicAuth():
            from secrets import token_hex
            from hashlib import sha1
            from base64 import b64encode
            client_id = "JuiUH&3822"
            client_secret = "HuUIC(ZQ918lkl*7"
            device_id = token_hex(32)
            hashed = sha1(f"{device_id}:{client_id}:{client_secret}".encode('utf-8')).hexdigest()
            basic = b64encode(bytes(f"{f'{device_id}_{client_id}'}:{hashed}", 'utf-8')).decode()
            return basic

        def login(email, password):
            print(f"Trying: {email} : {password}")
            paramz = {'grant_type':'password',
                      'username': email,
                      'password': password }

            header = {'Host': 'api.ifunny.mobi','Applicationstate': '1','Accept': 'video/mp4, image/jpeg','Content-Type': 'application/x-www-form-urlencoded; charset=utf-8','Authorization': 'Basic '+ basic,'Content-Length':'77','Ifunny-Project-Id': 'iFunny','User-Agent': 'iFunny/8.41.11(24194) iPhone/16.3.1 (Apple; iPhone12,5)','Accept-Language': 'en-US','Accept-Encoding': 'gzip, deflate'}
            userheader = {'Host': 'api.ifunny.mobi','Accept': 'video/mp4, image/jpeg','Applicationstate': '1','Accept-Encoding': 'gzip, deflate','Ifunny-Project-Id': 'iFunny','User-Agent': 'iFunny/8.41.11(24194) iPhone/16.3.1 (Apple; iPhone12,5)','Accept-Language': 'en-US;q=1','Authorization': 'Basic '+ basic,}
            index = 0

            while True:

                login = requests.post(host + "/v4/oauth2/token", headers=header, data=paramz).json()

                if "error" in login:

                    if login["error"] == "captcha_required":
                        print("Captcha required, Please solve the captcha, then press enter in this terminal: ")
                        time.sleep(3)
                        captcha_url = login["data"]["captcha_url"]
                        webbrowser.open_new(captcha_url)
                        input()
                        print("Logging in...")
                        continue

                    if login["error"] == "unsupported_grant_type":

                        time.sleep(10)
                        continue

                    if login["error"] == "too_many_user_auths":
                        raise print("auth rate succeeded, try again later")

                    if login["error"] == "forbidden":
                        index += 1
                        if index > 1:
                            raise print("Your email or password is incorrect! Please check your credentials and try again.")
                        requests.get(host+"/v4/counters", headers=userheader)
                        print("Priming one time use basic auth token...")
                        time.sleep(10)
                        continue

                    if login["error"] == "invalid_grant":
                        raise print("Your email or password is incorrect! Please check your credentials and try again.")

                    break

            bearer = login["access_token"]
            acctheader = {"Host":"api.ifunny.mobi","Accept":"video/mp4, image/jpeg","Applicationstate":"1","Ifunny-Project-Id":"iFunny",'User-Agent': 'iFunny/8.41.11(24194) iPhone/16.3.1 (Apple; iPhone12,5)',"Accept-Language": "en-US;q=1","Authorization":"Bearer " + bearer}
            Account = requests.get(host + "/v4/account", headers = acctheader).json()
            user_id = Account["data"]["id"]
            username = Account["data"]["original_nick"].replace("\n", "\\n")

            data = {
                "bearer": bearer,
                "user_id": user_id,
                "basic": basic
            }

            folder = "tokens"

            if not os.path.exists(folder):
                os.makedirs(folder)

            file_path = f"tokens/{username}.json"

            with open(file_path, "w") as f:
                json.dump(data, f, indent=4)

            print(f"Successful login for {username}")

        basic = generateBasicAuth()

        login(email, password)  # Pass arguments to login