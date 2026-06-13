FROM python:alpine

WORKDIR /app
COPY app.py .
COPY rich_client.py .
RUN pip install flask gunicorn

RUN apk add --no-cache \
    bash \
    tar \
    gzip \
    coreutils \
    procps \
    netcat-openbsd \
    sqlite \
    iputils \
    curl

CMD ["python", "app.py"]
