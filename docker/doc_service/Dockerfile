FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nginx && \
    rm -rf /var/lib/apt/lists/*
COPY state_paths.py ./state_paths.py
COPY docker/doc_service/app.py ./app.py
COPY docker/doc_service/requirements.txt ./requirements.txt
COPY docker/doc_service/start.sh ./start.sh
COPY docker/doc_service/nginx-internal.conf /etc/nginx/nginx-internal.conf
RUN pip install --no-cache-dir -r requirements.txt && \
    chmod +x ./start.sh && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/openssl/apps:${PATH}" LD_LIBRARY_PATH="/opt/openssl"
EXPOSE 5000 5443
CMD ["bash","./start.sh"]
