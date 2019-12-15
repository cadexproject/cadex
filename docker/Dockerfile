FROM debian:stretch
LABEL maintainer="Cadex Developers <dev@cadexcoin.tech>"
LABEL description="Dockerised Cadexcoin, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
