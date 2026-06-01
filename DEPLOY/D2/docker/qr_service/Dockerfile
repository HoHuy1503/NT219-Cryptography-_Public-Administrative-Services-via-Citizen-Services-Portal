FROM python:3.11-slim
WORKDIR /app
COPY docker/qr_service/app.py ./app.py
COPY docker/qr_service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5002
CMD ["python", "app.py"]