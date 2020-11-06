import hmac
import hashlib
import time
import requests
from http import cookiejar
import re
import json
import base64
from PIL import Image
import execjs
from urllib.parse import urlencode
import threading


class zhihu(object):


    def __init__(self, username: str = None, password: str = None):
        self.login_data = {
            'clientId': 'c3cef7c66a1843f8b3a9e6a1e3160e20',
            'grant_type': 'password',
            'source': 'com.zhihu.web',
            #'timestamp': int(time.time())*1000,
            #'signature':'',
            'username': username,
            'password': password,
            'captcha': '',
            'lang': 'en',
            'utm_source': '',
            'ref_source': 'other_https://www.zhihu.com/signin?next=%2F'
        }

        self.session = requests.session()
        self.session.headers = {
            'Host': 'www.zhihu.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
            'Referer': 'https://www.zhihu.com/signin?next=%2F',
            'accept-encoding': 'gzip, deflate, br'
        }

        self.session.cookies = cookiejar.LWPCookieJar(filename='./cookies.txt')

    def check_login(self):
        url = ' http://www.zhihu.com'
        resp = self.session.get(url)
        if resp.status_code == 302:
            self.session.cookies.save()
            return True
        else:
            return False


    def login(self, cap_lang = 'en'):
        if (self.check_login()):
            print("登陆成功-cookies")
            return
        else:
            print("没有cookies")

        self.check_user_pass()

        timestamp = int(time.time() * 1000)
        self.login_data.update({
            'timestamp': timestamp,
        })

        self.login_data.update({
            'signature': self._get_signature(),
            'captcha': self._get_captcha(self.login_data['lang']),
        })

        headers = self.session.headers.copy()
        headers.update({
            'content-type': 'application/x-www-form-urlencoded',
            'x-xsrftoken': self._get_xsrf(),
            'x-zse-83': '3_2.0',

        })

        data = self._encrypt(self.login_data)
        api = 'https://www.zhihu.com/api/v3/oauth/sign_in'
        post_resp = self.session.post(api, data=data, headers=headers)
        if post_resp == 'error':
            print('error')
        else:
            print("登陆成功")



    @staticmethod
    def _encrypt(form_data: dict):
        with open('./encrypt.js') as f:
            js = execjs.compile(f.read())
            return js.call('b', urlencode(form_data))




    def _get_captcha(self, lang):
        if (lang) == 'en':
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'
        elif (lang) == 'cn':
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=cn'

        resp = self.session.get(api)
        show_captcha = re.search(r'true', resp.text)  #返回match对象   .group(0) 获得匹配后的字符串
        #print(show_captcha.group())
        if show_captcha.group():
            put_resp = self.session.put(api)
            json_data = json.loads(put_resp.text)
            img_base64 = json_data['img_base64']#.replace(r'\n', '')
            with open("./captcha.jpg", 'wb') as f:
                f.write(base64.b64decode(img_base64))
            img = Image.open('./captcha.jpg')


            img_thread = threading.Thread(target=img.show, daemon=True)
            img_thread.start()
            # 这里可自行集成验证码识别模块
            input_captcha = input('输入验证码：')
            self.session.post(api, data={'input_text': input_captcha})
            return input_captcha
        return ''







    def _get_xsrf(self):
        """
            从登录页面获取 xsrf
            :return: str
        """
        self.session.get('http://www.zhihu.com')
        #print(self.session.cookies)
        for c in self.session.cookies:
            if c.name == '_xsrf':
                return c.value
        raise AssertionError('didnt find the xsrf')





    def _get_signature(self):
        """
            通过 Hmac 算法计算返回签名
            实际是几个固定字符串加时间戳
            :param timestamp: 时间戳
            :return: 签名
        """
        ha = hmac.new(b'd1b964811afb40118a12068ff74a12f4', digestmod=hashlib.sha1)
        grantType = self.login_data['grant_type']
        clientId = self.login_data['clientId']
        source = self.login_data['source']
        timestamp = self.login_data['timestamp'] #需要在登录时更新
        ha.update(bytes((grantType+clientId+source+str(timestamp)), 'utf-8'))
        return ha.hexdigest()

    def check_user_pass(self):
        if self.login_data['username'] == None:
            self.login_data['username'] = input("输入用户名: ")
        if self.login_data['password'] == None:
            self.login_data['password'] = input("输入密码: ")

if __name__ == '__main__':
    account = zhihu()
    account.login()






