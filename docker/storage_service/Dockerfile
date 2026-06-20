FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nginx && \
    rm -rf /var/lib/apt/lists/*
COPY state_paths.py ./state_paths.py
COPY docker/storage_service/app.py ./app.py
COPY docker/storage_service/jwt_auth.py ./jwt_auth.py
COPY docker/storage_service/requirements.txt ./requirements.txt
COPY docker/storage_service/start.sh ./start.sh
COPY docker/storage_service/nginx-internal.conf /etc/nginx/nginx-internal.conf
RUN pip install --no-cache-dir -r requirements.txt && chmod +x ./start.sh
ENV PATH="/opt/openssl/bin:${PATH}" LD_LIBRARY_PATH="/opt/openssl/lib:${LD_LIBRARY_PATH}"
EXPOSE 9003 9443
CMD ["bash","./start.sh"]
