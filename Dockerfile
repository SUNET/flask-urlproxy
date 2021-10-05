FROM debian:stable

MAINTAINER <pettai@sunet.se>

COPY . /opt/flask-urlproxy
COPY docker/setup.sh /setup.sh
COPY docker/start.sh /start.sh
RUN /setup.sh

EXPOSE 5000

WORKDIR /opt/flask-urlproxy

CMD ["bash", "/start.sh"]
