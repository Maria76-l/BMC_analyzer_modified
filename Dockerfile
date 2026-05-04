FROM python:3.10-slim

LABEL maintainer="company2-dev@example.com"
LABEL version="2.0.0"
LABEL description="BMC_analyzer — переход HTTP→HTTPS (MR-2026-001, ГОСТ 12207)"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=django_project.settings \
    DEBUG=False

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput 2>/dev/null || true

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:3000/login/ || exit 1

CMD ["gunicorn", "django_project.wsgi:application", "--bind", "0.0.0.0:3000", "--workers", "2", "--timeout", "120"]
