FROM python:3.11-slim
WORKDIR /app
COPY playbook/roles/doc_service/files/app.py ./app.py
COPY docker/doc_service/requirements.txt ./requirements.txt
COPY docker/doc_service/start.sh ./start.sh
RUN pip install --no-cache-dir -r requirements.txt && \
    chmod +x ./start.sh && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/openssl/apps:${PATH}" LD_LIBRARY_PATH="/opt/openssl"
EXPOSE 5000
CMD ["bash","./start.sh"]
