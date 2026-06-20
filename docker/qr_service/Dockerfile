FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nginx && \
    rm -rf /var/lib/apt/lists/*
COPY docker/qr_service/app.py ./app.py
COPY docker/qr_service/requirements.txt ./requirements.txt
COPY docker/qr_service/start.sh ./start.sh
COPY docker/qr_service/nginx-internal.conf /etc/nginx/nginx-internal.conf
RUN pip install --no-cache-dir -r requirements.txt && chmod +x ./start.sh
EXPOSE 5002 5443
CMD ["bash", "./start.sh"]
