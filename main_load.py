import hashlib
import json
import requests
from datetime import datetime

# 读取config.json文件
with open('config.json') as f:
    config = json.load(f)

# 提取用户名和密码
usernames_str = config.get("USERNAME_ARR")
passwords_str = config.get("PASSWORD_ARR")

if not usernames_str or not passwords_str:
    raise ValueError("Please set USERNAME_ARR and PASSWORD_ARR in config.json")

usernames = usernames_str.split(',')
passwords = passwords_str.split(',')

users = [{"username": username.strip(), "password": password.strip()} for username, password in zip(usernames, passwords)]


def generate_md5(s: str) -> str:
    """生成MD5加密的哈希值"""
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def sign(data: dict, sign_key: str) -> dict:
    """生成签名"""
    ts = str(int(datetime.now().timestamp()))
    data = {**data, 'ts': ts}
    sorted_data = {key: data[key] for key in sorted(data)}
    sorted_data['key'] = sign_key
    query_string = '&'.join(f"{key}={requests.utils.quote(str(value))}" for key, value in sorted_data.items())
    sign_value = generate_md5(query_string)
    return {**data, 'sign': sign_value, 'ts': ts}


class LeigodAPI:
    def __init__(self, token=None):
        self.token = token
        self.base_url = "https://webapi.leigod.com"
        self.headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'Referer': 'https://www.leigod.com/',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
        }

    def login(self, username, password):
        data = {
            'code': '',
            'country_code': 86,
            'lang': 'en',
            'os_type': 5,
            'password': generate_md5(password),
            'src_channel': 'guanwang',
            'region_code': 1,
            'user_type': '0',
            'username': username,
        }
        sign_key = '5C5A639C20665313622F51E93E3F2783'
        signed_data = sign(data, sign_key)

        response = requests.post(f"{self.base_url}/wap/login/bind/v1", json=signed_data, headers=self.headers)
        response_data = response.json()

        if response_data.get('code') == 0:
            self.token = response_data['data']['login_info']['account_token']
            return self.token
        else:
            raise Exception(response_data['msg'])

    def get_user_info(self):
        response = requests.post(
            f"{self.base_url}/api/user/info", 
            json={'account_token': self.token, 'lang': 'zh_CN'}, 
            headers=self.headers
        )
        response_data = response.json()

        if response.status_code == 403:
            raise Exception("Server error.")
        elif response_data.get('code') == 0:
            return response_data['data']
        else:
            raise Exception(response_data['msg'])

    def is_time_paused(self):
        user_info = self.get_user_info()
        status = user_info.get('pause_status_id')
        return status == 1

    def pause_time(self):
        response = requests.post(
            f"{self.base_url}/api/user/pause", 
            json={'account_token': self.token, 'lang': 'zh_CN'}, 
            headers=self.headers
        )
        response_data = response.json()

        if response.status_code == 403:
            raise Exception("Server error.")
        return response_data.get('msg')

    def recover_time(self):
        response = requests.post(
            f"{self.base_url}/api/user/recover", 
            json={'account_token': self.token, 'lang': 'zh_CN'}, 
            headers=self.headers
        )
        response_data = response.json()

        if response.status_code == 403:
            raise Exception("Server error.")
        return response_data.get('msg')


def hide_string(s: str) -> str:
    """隐藏字符串的部分内容"""
    if not s:
        return ''
    return s[:3] + '****' + s[-4:]


def pause(username, password):
    hide_name = hide_string(username)
    leigod_api = LeigodAPI()

    if username and password:
        try:
            print(f"{hide_name}: Logging in")
            leigod_api.login(username, password)
            is_paused = leigod_api.is_time_paused()
            print(f"{hide_name}: Getting pause status: {is_paused}")

            if not is_paused:
                print(f"{hide_name}: Time is not paused, trying to pause time")
                leigod_api.pause_time()
                is_paused = leigod_api.is_time_paused()
                print(f"{hide_name}: Getting pause status again: {is_paused}")

        except Exception as e:
            print(f"{hide_name}: {str(e)}")
            return False
    else:
        print(f"{hide_name}: The username or password is empty, please check config.json")
        return False

    return True


if __name__ == "__main__":
    success_flag = True

    for user in users:
        username = user['username']
        password = user['password']
        result = pause(username, password)
        success_flag = success_flag and result
        print('-----------------------')

    if not success_flag:
        print('Something went wrong! please check the logs.')
