# -*- coding: utf-8 -*-
from threading import Thread  # 並列処理
from multiprocessing import Manager  # スレッド間での値の共有
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
import json


def loop_handler():
    global commentbody
    global clients
    while True:
        comment = commentbody
        commentbody = []
        if not len(comment):
            for i in clients:
                try:
                    i[0].sendall("PING".encode())
                except socket.error:
                    clients = [j for j in clients if j[0] != i[0]]
                    logging.info("Disconnected")
            continue
        for i in clients:
            conn = i[0]
            if not comment[1] in i:
                continue
            conn.sendall(comment[0])
            print("send: " + str(comment[0]))
            comment = []
            break


def connect_socket():  # Socket通信
    global is_connected
    logging.info("SocketStart")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 10023))  # ポート10023で開放
        while True:
            s.listen(5)  # 接続待ち
            logging.info("Waitng ....")
            is_connected = False
            conn, addr = s.accept()
            try:
                conn = context.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                continue
            except Exception as e:
                print(e)
            # with conn:
            logging.info("Connecting")
            while True:
                data = conn.recv(1024).decode()
                try:
                    if not data and not is_connected:
                        break
                    elif "password" in data and "username" in data:  # 認証データ受け取り
                        data = json.loads(data)
                        c = database.cursor()
                        loginuser = data['username']
                        loginpass = data['password']
                        # ユーザーをデータベースで検索
                        sql = "SELECT id, name, pass FROM users WHERE name = %s"
                        c.execute(sql, (loginuser,))
                        userdata = c.fetchall()
                        c.close()
                        auth_result = False
                        # パスワードを検証
                        if not len(userdata):
                            break
                        auth_result = bcrypt.checkpw(
                            loginpass.encode(),
                            userdata[0][2].encode()
                        )
                        # 認証成功時
                        if len(userdata) and auth_result:
                            logging.info("Connected")
                            conn.send("接続完了".encode("utf-8"))
                            clients.append((
                                conn, addr, secrets.token_urlsafe()))
                        # 認証失敗時
                        else:
                            conn.send("認証エラー".encode("utf-8"))
                            conn.close()
                            break

                # 切断時
                except socket.error:
                    logging.info("Disconnected")
                    break


def send_comment(comment, token):
    global commentbody
    # 現在時刻(JST)
    dt_now = dt.now(JST)
    c = database.cursor()
    sql = "INSERT INTO comment (text, entertime) values(%s,%s)"
    c.execute(sql, (comment.encode('utf-8'), dt_now,))
    database.commit()
    commentbody = [comment.encode(), token]
    c.close()


class BaseHandler(web.RequestHandler):  # ユーザーセッション
    def get_current_user(self):  # 現在のユーザー
        username = self.get_secure_cookie("user")
        if not username:
            return None
        return tornado.escape.utf8(username)

    def set_current_user(self, username):  # 現在のユーザーを設定
        self.set_secure_cookie("user", tornado.escape.utf8(username))

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


class Comment(web.RequestHandler):  # コメント入力フォーム
    def post(self):
        cl = self.get_argument("token")
        for i in clients:
            if not (cl in i):
                continue
            comment = self.get_argument("comment")
            comment = escape(comment)
            title = "PSS | Comment"
            if len(comment) < 30:
                send_comment(comment, cl)
                self.redirect(f'/Comment?cl={cl}')
            else:
                token = cl
                message = "正しく入力してください"
                self.render('comment.html', title=title,
                            message=message, token=token)

    def get(self):
        cl = self.get_query_argument("cl", default=0)
        find = False
        if cl == 0:
            self.redirect('/ClientList')
        else:
            for i in clients:
                if not (cl in i):
                    continue
                title = "PSS | コメント入力"
                find = True
                self.render('comment.html', title=title, message="", token=cl)
        if not find:
            title = "PSS | コメント入力"
            self.render('comment_stop.html', title=title, message="NOT FOUND")


class ClientList(web.RequestHandler):
    def get(self):
        title = "PSS | クライアント一覧"
        clients_list = []
        for i in clients:
            clients_list.append(i[2])
        self.render('list.html', title=title, clients_list=clients_list)


class MainHandler(web.RequestHandler):  # トップページ
    def get(self):
        title = "PSS | TOP"
        self.render('index.html', title=title)


def webapp_main():
    logging.info("AppStart")
    asyncio.set_event_loop(asyncio.new_event_loop())
    BASE_DIR = os.getcwd()
    token = secrets.token_hex()
    application = web.Application(
        [(r"/", MainHandler),
         (r"/Login", AuthLoginHandler),
         (r"/Logout", AuthLogoutHandler),
         (r"/Comment", Comment),
         (r"/DashBoard", DashBoard),
         (r"/CommentHistory", CommentHistory),
         (r"/AccountSettings", AccountSettings),
         (r"/ClientList", ClientList),
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
    clients = []
    manager = Manager()
    commentbody = manager.list()
    # データベースの設定(ユーザー名・パスワード)読み込み
    yaml_dict = yaml.load(open('Web/secret.yaml').read(),
                          Loader=yaml.SafeLoader)
    user_name, DBPASS = yaml_dict['username'], yaml_dict['password']
    # タイムゾーンをJSTに設定
    JST = timezone(timedelta(hours=+9), 'JST')
    # SocketのSSL化
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(
        certfile="/Web/keyfile/server.crt",
        keyfile="/Web/keyfile/server.key"
    )
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
    thread4 = Thread(target=loop_handler)
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
