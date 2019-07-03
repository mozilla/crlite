FROM python:3.7-stretch
RUN apt update && apt install -y ca-certificates && \
    apt -y upgrade && apt-get autoremove --purge -y && \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --system --home /app appuser
COPY requirements.txt /app/
RUN pip3 install -r /app/requirements.txt

USER appuser
COPY create_filter_cascade /app/create_filter_cascade
COPY kinto-publisher /app/kinto-publisher

WORKDIR /app
VOLUME /var/log /ctdata /processing /config
