FROM python:3.12-slim

WORKDIR /app

# Buenas prácticas básicas
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# App Platform suele inyectar $PORT; si no, usamos 8000 por defecto
CMD ["sh", "-c", "uvicorn insecure_api:app --host 0.0.0.0 --port ${PORT:-8000}"]
