# DEPLOY/D1/qr-service/Dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask redis cryptography
COPY app.py .
EXPOSE 5002
CMD ["python", "app.py"]
