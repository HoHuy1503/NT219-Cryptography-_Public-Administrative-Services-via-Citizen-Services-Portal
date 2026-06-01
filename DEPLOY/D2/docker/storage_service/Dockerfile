FROM python:3.11-slim
WORKDIR /app
COPY playbook/roles/storage_service/files/app.py ./app.py
COPY docker/storage_service/requirements.txt ./requirements.txt
COPY docker/storage_service/start.sh ./start.sh
RUN pip install --no-cache-dir -r requirements.txt && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN chmod +x ./start.sh
ENV PATH="/opt/openssl/bin:${PATH}" LD_LIBRARY_PATH="/opt/openssl/lib:${LD_LIBRARY_PATH}"
EXPOSE 5001
CMD ["bash","./start.sh"]
