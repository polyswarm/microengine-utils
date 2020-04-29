FROM python:3.6-alpine

WORKDIR /usr/src/app

RUN apk add --no-cache openssl git build-base libffi-dev openssl-dev libmagic

ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz

COPY requirements.* ./
RUN pip install --no-cache-dir --upgrade -r requirements.txt -r requirements.test.txt

COPY . .
RUN set -x && pip install .
