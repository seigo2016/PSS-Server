# -*- coding: utf-8 -*-
from multiprocessing import Value
import bcrypt
import mysql.connector as mydb
from xml.sax.saxutils import escape
import re
from datetime import datetime as dt
from datetime import timezone, timedelta
import asyncio
import socket
import tornado
import ssl
from threading import Thread
from tornado import httpserver, web, ioloop
import os
import ctypes
import secrets
import logging
import yaml

# データベースの設定読み込み
yaml_dict = yaml.load(open('Web/secret.yaml').read(), Loader=yaml.SafeLoader)
user_name, DBPASS = yaml_dict['username'], yaml_dict['password']

# JSTを設定
JST = timezone(timedelta(hours=+9), 'JST')
commentbody = Value(ctypes.c_char_p, ''.encode())
# SocketのSSL設定
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="/Web/server.pem", keyfile="/Web/server.key")
flg = False
# データベースの接続設定
database = mydb.connect(
    user=user_name,
    passwd=DBPASS,
    host='mysql',
    port=3306,
    db='PSS'
)


def connect_socket():  # Socket通信
    global flg
    print("SocketStart")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 10023))  # ポート10023で開放
        while True:
            s.listen(1)  # 接続待ち
            print("Waitng ....")
            flg = False
            conn, addr = s.accept()
            while True:
                try:
                    conn = context.wrap_socket(conn, server_side=3)
                    with conn:
                        print("Connecting")
                        while True:
                            try:
                                data = conn.recv(1024).decode()
                                if not data:
                                    break
                                elif ":" in data:  # 認証データ受け取り
                                    c = database.cursor()
                                    loginuser = data.split(":")[0]
                                    loginpass = data.split(":")[1]
                                    # ユーザーをデータベースで検索
                                    sql = "SELECT id, name, pass FROM users WHERE name = %s"
                                    c.execute(sql, (loginuser,))
                                    userdata = c.fetchall()
                                    c.close()
                                    # パスワードを検証
                                    auth_result = bcrypt.checkpw(
                                        loginpass.encode(),
                                        userdata[0][2].encode()
                                    )
                                    # 認証成功時
                                    if len(userdata) and auth_result:
                                        print("Connected")
                                        conn.sendall(
                                            "接続完了".encode("utf-8"))
                                        flg = True
                                    # 認証失敗時
                                    else:
                                        print("Auth error")
                                        conn.sendall(
                                            "認証エラー".encode("utf-8"))
                                        conn.close()
                                        break
                                # 認証後コメント送信
                                elif flg:
                                    comment = commentbody.value
                                    with commentbody.get_lock():
                                        commentbody.value = "".encode()
                                    if len(comment):
                                        conn.sendall(comment)
                                        comment = ""
                            # 切断時
                            except socket.error:
                                print(f"Disconnected")
                                break
                except Exception as e:
                    print(f'{e}')
                    break
            conn.close()


class BaseHandler(web.RequestHandler):  # ユーザーセッション
    def get_current_user(self):
        username = self.get_secure_cookie("user")
        if not username:
            return None
        return tornado.escape.utf8(username)

    def set_current_user(self, username):
        self.set_secure_cookie("user",
                               tornado.escape.utf8(username))

    def clear_current_user(self):
        self.clear_cookie("user")


class AuthLogoutHandler(BaseHandler):  # ログアウト処理
    def get(self):
        self.clear_current_user()
        self.redirect('/')


class AuthLoginHandler(BaseHandler):  # ログイン処理
    def get(self):  # ログインページ表示
        self.render("login.html", title="ログイン", message="ログイン")

    def post(self):  # ログイン処理
        logging.debug("xsrf_cookie:" + self.get_argument("_xsrf", None))
        self.check_xsrf_cookie()
        username = self.get_argument("LoginName")
        password = self.get_argument("LoginPass")
        # パスワードとユーザーが入力されていた場合
        if len(username) and len(password):
            c = database.cursor()
            # ユーザーをデータベースで検索
            sql = "SELECT id, name, pass FROM users WHERE name = %s"
            c.execute(sql, (username,))
            userdata = c.fetchall()
            c.close()
            if len(userdata):
                # 認証成功時
                if bcrypt.checkpw(password.encode(), userdata[0][2].encode()) and username == username:
                    self.set_secure_cookie("user", username)
                    self.set_current_user(username)
                    self.redirect("/DashBoard")
                # 認証失敗時(パスワードが違う場合)
                else:
                    print("AuthError")
                    self.render('login.html', title="ログイン",
                                message="パスワードかパスワードが違います")
            # 認証失敗時(ユーザー自体が登録されていない場合)
            else:
                print("ID or PassWord is Null")
                self.render('login.html', title="ログイン",
                            message="パスワードかパスワードが違います")
        # 入力されていないとき
        else:
            print("ID or PassWord is Null")
            self.render('login.html', title="ログイン", message="正しく入力してください")


class CommentHistory(BaseHandler):  # コメントの履歴を表示(要ログイン)
    @web.authenticated
    def get(self):
        title = "コメント履歴"
        # データベースから履歴を取得
        c = database.cursor()
        sql = "SELECT text, entertime FROM comment"
        c.execute(sql)
        comment_list = c.fetchall()
        database.commit()
        c.close()
        comment = [[None for i in range(2)]
                   for i in range(len(comment_list))]
        # コメント一覧を生成(json)
        for i, x in enumerate(comment_list):
            comment[i] = {'date': x[1].strftime(
                '%Y-%m-%d %H:%M:%S'), 'text': x[0]}
            comment[i] = tornado.escape.json_encode(comment[i])
        self.render('history.html', title=title, message=comment)


class AccountSettings():
    @web.authenticated
    def get(self):
        title = "PSS | AccountSettings"
        self.render('accountsettings.html', title=title)

    def post(self):
        title = "PSS | AccountSettings"
        
        pass


class DashBoard(BaseHandler):
    @web.authenticated
    def get(self):
        title = "PSS | DashBoard"
        self.render('dashboard.html', title=title)


def send_comment(comment):
    # 現在時刻(JST)
    dt_now = dt.now(JST)
    c = database.cursor()
    sql = "INSERT INTO comment (text, entertime) values(%s,%s)"
    c.execute(sql,
              (comment, dt_now,))
    database.commit()
    with commentbody.get_lock():
        commentbody.value = comment.encode()
    c.close()


class Comment(web.RequestHandler):
    def post(self):
        comment = self.get_argument("comment")
        comment = escape(comment)
        title = "PSS | Comment"
        if len(comment) < 30:
            send_comment(comment)
            self.render('comment.html', title=title)
        else:
            message = "正しく入力してください"
            self.render('comment.html', title=title, message=message)

    def get(self):
        if flg:
            title = "PSS | コメント入力"
            self.render('comment.html', title=title)
        else:
            title = "PSS | コメント入力"
            self.render('comment_stop.html', title=title,
                        message="現在コメント可能なプレゼンテーションはありません")


class MainHandler(web.RequestHandler):
    def get(self):
        title = "PSS | TOP"
        self.render('index.html', title=title)


def main():
    print("AppStart")
    asyncio.set_event_loop(asyncio.new_event_loop())
    BASE_DIR = os.getcwd()
    token = secrets.token_hex()
    # Tornadoの設定
    application = web.Application(
        [(r"/", MainHandler),
            (r"/Login", AuthLoginHandler), (r"/Logout", AuthLogoutHandler),
            (r"/Comment", Comment), (r"/DashBoard", DashBoard), (r"/CommentHistory", CommentHistory), (r"/AccountSettings", AccountSettings)],
        # Webページテンプレートのディレクトリ
        template_path=os.path.join(BASE_DIR, 'Web/templates'),
        cookie_secret=token,
        # 静的ファイルのディレクトリ
        static_path=os.path.join(BASE_DIR, "Web/static"),
        login_url="/Login",
        xsrf_cookies=True,
        autoescape="xhtml_escape")
    # 鍵ファイル設定
    server = httpserver.HTTPServer(application, ssl_options={
        'certfile': 'server.pem',
        'keyfile': 'server.key'
    })
    # ポート5000
    server.listen(5000, '0.0.0.0')
    ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    # Webアプリケーション部分
    thread1 = Thread(target=main)
    # ソケット通信部分
    thread2 = Thread(target=connect_socket)

    thread1.start()
    thread2.start()
