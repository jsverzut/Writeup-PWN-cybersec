# syntax=docker/dockerfile:1

# As libs 2.19 já entram na imagem a partir de ./lib.
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir pwntools unicorn pyelftools

WORKDIR /app

# Código, binário do desafio e scripts de validação.
COPY zerostorage ./
COPY exploit.py ./

# Loader + libc 2.19 já extraídos (substituem o setup_219.sh).
COPY lib/ ./lib/

# Confere a libc e o loader em tempo de build.
RUN chmod +x /app/lib/ld-2.19.so /app/exploit.py \
 && echo "0b9dd2a74703d2d45b3ea406eee86bd3  /app/lib/ld-2.19.so" | md5sum -c - \
 && echo "ac6e8213081cc6f5a16779214a90d952  /app/lib/libc.so.6" | md5sum -c -

# Por padrão abre a shell pela cadeia da libc 2.19.
CMD ["python3", "exploit.py"]
