FROM python:3.11-slim
WORKDIR /app
COPY state_paths.py ./state_paths.py
COPY docker/authz_proxy/app.py ./app.py
COPY docker/authz_proxy/requirements.txt ./requirements.txt
COPY docker/storage_service/jwt_auth.py ./jwt_auth.py
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 9191
CMD ["python3", "app.py"]
