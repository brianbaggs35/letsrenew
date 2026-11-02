FROM node:24-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm install --global npm@12.2.1 && npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.14.8-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/data \
    PYTHONUSERBASE=/data/python
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt
COPY backend/app.py ./app.py
COPY --from=frontend /build/dist ./static
RUN mkdir -p /data && chown -R 10001:10001 /data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; request = urllib.request.Request('http://127.0.0.1:8000/api/health', headers={'Authorization': 'Bearer ' + os.environ['APP_PASSWORD']}); urllib.request.urlopen(request, timeout=3)"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
