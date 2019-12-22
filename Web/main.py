# -*- coding: utf-8 -*-

from threading import Thread  # 並列処理
from multiprocessing import Value  # スレッド間での値の共有
import ctypes  # スレッド間での値を共有する際の型指定
import asyncio  # 非同期処理
import mysql.connector as mydb  # データベース接続用
import bcrypt  # ログインパスワードのハッシュ化・検証
import ssl  # ソケット通信のSSL化
import secrets  # セキュアなCookie_Seacretsの生成
from xml.sax.saxutils import escape  # HTMLエスケープ
from datetime import datetime as dt  # 時刻取得
from datetime import timezone, timedelta  # タイムゾーン(JST)設定
import socket  # ソケット通信
import tornado  # Webアプリケーションフレームワーク
from tornado import httpserver, web, ioloop  # Webアプリケーションフレームワーク
import os  # パス取得用
import yaml  # データベース等の設定をyamlから取得
import logging  # ログ取得
import time

def connect_socket():  # Socket通信
    global is_connected
    logging.info("SocketStart")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 10023))  # ポート10023で開放
        while True:
            s.listen(1)  # 接続待ち
            logging.info("Waitng ....")
            is_connected = False
            conn, addr = s.accept()
            while True:
                try:
                    conn = context.wrap_socket(conn, server_side=3)
                    with conn:
                        logging.info("Connecting")
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
                                        logging.info("Connected")
                                        conn.sendall(
                                            "接続完了".encode("utf-8"))
                                        is_connected = True
                                    # 認証失敗時
                                    else:
                                        print("Auth error")
                                        conn.sendall(
                                            "認証エラー".encode("utf-8"))
                                        conn.close()
                                        break
                                # 認証後コメント送信
                                elif is_connected:
                                    comment = commentbody.value
                                    print(comment)
                                    with commentbody.get_lock():
                                        commentbody.value = "".encode()
                                    if len(comment):
                                        conn.sendall(comment)
                                        comment = ""
                            # 切断時
                            except socket.error:
                                logging.info(f"Disconnected")
                                break
                except Exception as e:
                    logging.warning(f'{e}')
                    break
            conn.close()


class BaseHandler(web.RequestHandler):  # ユーザーセッション
    def get_current_user(self):  # 現在のユーザー
        username = self.get_secure_cookie("user")
        if not username:
            return None
        return tornado.escape.utf8(username)

    def set_current_user(self, username):  # 現在のユーザーを設定
        self.set_secure_cookie("user",
                               tornado.escape.utf8(username))

    def clear_current_user(self):  # 現在のユーザーをクリア
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
                try:  # 認証成功
                    auth = bcrypt.checkpw(
                        password.encode(), userdata[0][2].encode())
                    auth = True
                except ValueError:  # 認証失敗
                    auth = False
                if auth and username == username:
                    self.set_secure_cookie("user", username)
                    self.set_current_user(username)
                    self.redirect("/DashBoard")
                else:  # 認証失敗時(パスワードが違う場合)
                    logging.info("AuthError")
                    self.render('login.html', title="ログイン",
                                message="IDかパスワードが違います")
            # 認証失敗時(ユーザー自体が登録されていない場合)
            else:
                logging.info("User not found")
                self.render('login.html', title="ログイン",
                            message="IDかパスワードが違います")
        # 入力されていないとき
        else:
            logging.info("ID or PassWord is Null")
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


class AccountSettings(BaseHandler):
    @web.authenticated
    def get(self):
        title = "PSS | AccountSettings"
        self.render('accountsettings.html', title=title, message="")

    def post(self):
        logging.debug("xsrf_cookie:" + self.get_argument("_xsrf", None))
        self.check_xsrf_cookie()
        current_password = self.get_argument("current_password")
        new_password = self.get_argument("new_password")
        username = self.get_current_user()
        if len(current_password) and len(new_password):
            c = database.cursor()
            # ユーザーをデータベースで検索
            sql = "SELECT id, name, pass FROM users WHERE name = %s"
            c.execute(sql, (username,))
            userdata = c.fetchall()
            # 認証成功時
            if bcrypt.checkpw(current_password.encode(), userdata[0][2].encode()):
                sql = "UPDATE users SET pass = %s WHERE name = %s"
                salt = bcrypt.gensalt(rounds=10, prefix=b'2a')
                hashed_password = bcrypt.hashpw(new_password.encode(), salt)
                c.execute(sql, (hashed_password, username,))
                database.commit()
                title = "PSS | AccountSettings"
                logging.info("Complete change password")
                self.render('accountsettings.html',
                            title=title, message="パスワードを変更しました")
            # 認証失敗時(パスワードが違う場合)
            else:
                logging.info("AuthError")
                title = "PSS | AccountSettings"
                self.render('accountsettings.html', title=title,
                            message="現在のパスワードが違います")
            c.close()


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


class Comment(web.RequestHandler):  # コメント入力フォーム
    def post(self):
        comment = self.get_argument("comment")
        # エスケープ
        comment = escape(comment)
        title = "PSS | Comment"
        # コメント文字数制限(30)
        if len(comment) < 30:
            send_comment(comment)
            self.render('comment.html', title=title)
        else:
            message = "正しく入力してください"
            self.render('comment.html', title=title, message=message)

    def get(self):
        if is_connected:  # プレゼンテーターのPCが接続しているか
            title = "PSS | コメント入力"
            self.render('comment.html', title=title)
        else:
            title = "PSS | コメント入力"
            self.render('comment_stop.html', title=title,
                        message="現在コメント可能なプレゼンテーションはありません")


class MainHandler(web.RequestHandler):  # トップページ
    def get(self):
        title = "PSS | TOP"
        self.render('index.html', title=title)


def webapp_main():
    logging.info("AppStart")
    asyncio.set_event_loop(asyncio.new_event_loop())
    BASE_DIR = os.getcwd()
    token = secrets.token_hex()
    # Tornadoの設定
    application = web.Application(
        [(r"/", MainHandler),
         (r"/Login", AuthLoginHandler),
         (r"/Logout", AuthLogoutHandler),
         (r"/Comment", Comment),
         (r"/DashBoard", DashBoard),
         (r"/CommentHistory", CommentHistory),
         (r"/AccountSettings", AccountSettings),
         (r'/(favicon.ico)', tornado.web.StaticFileHandler, {"url": "/static/favicon.png"})],
        template_path=os.path.join(BASE_DIR, 'Web/templates'),
        cookie_secret=token,
        static_path=os.path.join(BASE_DIR, "Web/static"),
        login_url="/Login",
        xsrf_cookies=True,
        autoescape="xhtml_escape"
    )
    # 鍵ファイル設定
    server = httpserver.HTTPServer(
        application,
        ssl_options={
            'certfile': 'server.pem',
            'keyfile': 'server.key'
        }
    )
    server.listen(5000, '0.0.0.0')
    ioloop.IOLoop.instance().start()


def db_ping():
    while True:
        database.ping(reconnect=True)
        time.sleep(180)


if __name__ == '__main__':
    # データベースの設定(ユーザー名・パスワード)読み込み
    yaml_dict = yaml.load(open('Web/secret.yaml').read(),
                          Loader=yaml.SafeLoader)
    user_name, DBPASS = yaml_dict['username'], yaml_dict['password']
    # タイムゾーンをJSTに設定
    JST = timezone(timedelta(hours=+9), 'JST')
    commentbody = Value(ctypes.c_char_p, ''.encode())
    # SocketのSSL化
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="/Web/server.pem",
                            keyfile="/Web/server.key")
    is_connected = False
    # データベースの接続設定
    database = mydb.connect(
        user=user_name,
        passwd=DBPASS,
        host='mysql',
        port=3306,
        db='PSS'
    )
    logging.basicConfig(filename='/log/server.log', level=logging.DEBUG)
    # Webアプリケーションスレッド
    thread1 = Thread(target=webapp_main)
    # ソケット通信スレッド
    thread2 = Thread(target=connect_socket)
    thread3 = Thread(target=db_ping)
    thread1.start()
    thread2.start()
    thread3.start()
