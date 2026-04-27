FROM ubuntu/squid:latest

COPY squid.conf /etc/squid/squid.conf
RUN mkdir -p /var/log/squid && chown -R proxy:proxy /var/log/squid

EXPOSE 3128
