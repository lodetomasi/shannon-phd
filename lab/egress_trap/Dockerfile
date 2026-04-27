FROM python:3.12-slim

RUN useradd -r -u 1001 trap && mkdir -p /var/log/egress-trap && chown -R trap /var/log/egress-trap
COPY server.py /opt/trap/server.py

USER trap
EXPOSE 53/udp
EXPOSE 80/tcp
ENTRYPOINT ["python", "/opt/trap/server.py"]
CMD ["--dns-port", "53", "--http-port", "80", "--bind", "0.0.0.0", "--log", "/var/log/egress-trap/events.jsonl"]
