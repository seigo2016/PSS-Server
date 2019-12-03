FROM ubuntu:latest

RUN apt-get update
RUN apt-get install python3 python3-pip -y 

RUN pip3 install tornado bcrypt mysql-connector
EXPOSE 5000
EXPOSE 443
#RUN mkdir openssl
#RUN cd openssl
# RUN openssl req -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj "/C=JP/ST=Tokyo/L=Tokyo/O=N INC./OU=IT Department/CN=seigo2016.com" && openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt
#RUN openssl genrsa 2048 > server.key
#RUN openssl req -new -key server.key > server.csr
#RUN openssl x509 -days 3650 -req -signkey server.key < server.csr > server.crt
RUN cd ../
WORKDIR /Web
ADD . /Web
#RUN openssl req -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj "/C=JP/ST=Tokyo/L=Tokyo/O=N INC./OU=IT Department/CN=seigo2016.com" && openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt
ADD ./fullchain.pem /Web/server.pem
ADD ./privkey.pem /Web/server.key
CMD ["python3","-u","Web/main.py"]
