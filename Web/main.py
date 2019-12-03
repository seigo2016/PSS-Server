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

yaml_dict = yaml.load(open('Web/secret.yaml').read())
user_name, password = yaml_dict['username'], yaml_dict['password']

# DBPASS = os.environ.get('DBPASS')
DBPASS = "password"
JST = timezone(timedelta(hours=+9), 'JST')
commentbody = Value(ctypes.c_char_p, ''.encode())
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="/Web/server.pem", keyfile="/Web/server.key")


def connect_socket():
    print("SocketStart")
    database = mydb.connect(
        user='root',
        passwd=DBPASS,
        host='mysql',
        port=3306,
        db='PSS'
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 10023))
        s.listen(1)
        while True:
            try:
                print("Waitng ....")
                conn, addr = s.accept()
                conn = context.wrap_socket(conn, server_side=3)
                close = False
                with conn:
                    while not close:
                        print("Connecting")
                        data = conn.recv(1024).decode()
                        if not data:
                            break
                        elif ":" in data:
                            username = data.split(":")[0]
                            userpass = data.split(":")[1]
                            c = database.cursor()
                            sql = "SELECT id, name, pass FROM users WHERE name = %s"
                            c.execute(sql, (username,))
                            userdata = c.fetchall()
                            if len(userdata) > 0:
                                if bcrypt.checkpw(userpass.encode(), userdata[0][2].encode()):
                                    print("Connected")
                                    conn.sendall("合致しました".encode("utf-8"))
                                    while True:
                                        comment = commentbody.value
                                        with commentbody.get_lock():
                                            commentbody.value = "".encode()
                                        while not close and (len(comment) != 0):
                                            print("send:" + str(comment))
                                            conn.sendall(comment)
                                            comment = ""
                                else:
                                    close = True
                                    conn.sendall("認証エラー".encode("utf-8"))
            except Exception as e:
                print(e)
                print("Disconnected")
                pass
            close = True
        c.close()
        database.close()
        s.close()


class BaseHandler(web.RequestHandler):

    def get_current_user(self):
        username = self.get_secure_cookie("user")
        # logging.debug('BaseHandler - username: %s' % username)
        if not username:
            return None
        return tornado.escape.utf8(username)

    def set_current_user(self, username):
        self.set_secure_cookie("user",
                               tornado.escape.utf8(username))

    def clear_current_user(self):
        self.clear_cookie("user")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_current_user()
        self.redirect('/')


class AuthLoginHandler(BaseHandler):

    def get(self):
        self.render("login.html", title="ログイン", message="ログイン")

    def post(self):
        logging.debug("xsrf_cookie:" + self.get_argument("_xsrf", None))
        database = mydb.connect(
            user='root',
            passwd=DBPASS,
            host='mysql',
            port=3306,
            db='PSS'
        )
        self.check_xsrf_cookie()

        username = self.get_argument("LoginName")
        password = self.get_argument("LoginPass")
        if len(username) != 0 and len(password):
            c = database.cursor()
            sql = "SELECT id, name, pass FROM users WHERE name = %s"
            c.execute(sql, (username,))
            userdata = c.fetchall()
            c.close()
            if bcrypt.checkpw(password.encode(), userdata[0][2].encode()) and username == username:
                self.set_secure_cookie("user", username)
                self.set_current_user(username)
                self.redirect("/")
            else:
                self.write_error(403)


class CommentHistory(BaseHandler):
    @web.authenticated
    def get(self):
        database = mydb.connect(
            user='root',
            passwd=DBPASS,
            host='mysql',
            port=3306,
            db='PSS'
        )
        title = "コメント履歴"
        c = database.cursor()
        sql = "SELECT text, entertime FROM comment"
        c.execute(sql)
        comment_list = c.fetchall()
        c.close()
        database.commit()
        database.close()
        comment = [[None for i in range(2)]
                   for i in range(len(comment_list))]
        for i, x in enumerate(comment_list):
            comment[i][0] = x[0]
            comment[i][1] = x[1].strftime('%Y-%m-%d %H:%M:%S')
        self.render('history.html', title=title, message=comment)


def send_comment(comment):
    database = mydb.connect(
        user='root',
        passwd=DBPASS,
        host='mysql',
        port=3306,
        db='PSS'
    )
    dt_now = dt.now(JST)
    c = database.cursor()
    sql = "INSERT INTO comment (text, entertime) values(%s,%s)"
    c.execute(sql,
              (comment, dt_now,))
    database.commit()
    commentbody.value = (comment).encode()
    with commentbody.get_lock():
        commentbody.value = comment.encode()


class Comment(web.RequestHandler):
    def post(self):
        comment = self.get_argument("comment")
        comment = escape(comment)
        title = "コメント"
        if re.search(r'\S', comment) and len(comment) < 30:
            send_comment(comment)
            self.render('index.html', title=title)
        else:
            message = "正しく入力してください"
            self.render('index.html', title=title, message=message)


class MainHandler(web.RequestHandler):
    def get(self):
        title = "コメント機能"
        self.render('index.html', title=title)


def main():
    print("AppStart")
    asyncio.set_event_loop(asyncio.new_event_loop())
    BASE_DIR = os.path.dirname(__file__)
    token = secrets.token_hex()
    application = web.Application(
        [(r"/", MainHandler),
            (r"/Login", AuthLoginHandler), (r"/Logout", AuthLogoutHandler),
            (r"/Comment", Comment), (r"/CommentHistory", CommentHistory)],
        template_path=os.path.join(BASE_DIR, 'templates'),
        cookie_secret=token,
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        login_url="/Login",
        xsrf_cookies=True,
        autoescape="xhtml_escape")
    server = httpserver.HTTPServer(application, ssl_options={
        'certfile': 'server.pem',
        'keyfile': 'server.key'
    })
    server.listen(5000, '0.0.0.0')
    ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    thread1 = Thread(target=main)
    thread2 = Thread(target=connect_socket)

    thread1.start()
    thread2.start()
