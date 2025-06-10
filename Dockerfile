FROM python:3.12-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apk update && apk add --no-cache \
    gcc \
    musl-dev \
    python3-dev

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apk update && apk add --no-cache \
    openssl \
    #curl \
    #netcat-openbsd
    && rm -rf /var/cache/apk/*

WORKDIR /bubo

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY main.py .
COPY ./bubo ./bubo

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]