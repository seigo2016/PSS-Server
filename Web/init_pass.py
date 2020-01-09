import bcrypt
import yaml
import mysql.connector as mydb

# データベースの設定読み込み
yaml_dict = yaml.load(open('Web/secret.yaml').read(), Loader=yaml.SafeLoader)
init_user, init_pass = yaml_dict['init_user'], yaml_dict['init_pass']
user_name, DBPASS = yaml_dict['username'], yaml_dict['password']

salt = bcrypt.gensalt(rounds=10, prefix=b'2a')
password = init_pass.encode()
password = bcrypt.hashpw(password, salt)
# データベースの接続設定
database = mydb.connect(
    user=user_name,
    passwd=DBPASS,
    host='mysql',
    port=3306,
    db='PSS'
)
c = database.cursor()
sql = "Insert INTO users (name, pass) values(%s,%s)"
c.execute(sql, (init_user, password,))
database.commit()
database.close()
