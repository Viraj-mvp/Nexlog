FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --shell /bin/bash nexlog \
    && mkdir -p /data/cases /data/uploads /data/reports \
    && chown -R nexlog:nexlog /data /app

USER nexlog

ENV PYTHONPATH="/app:/app/nexlog"
ENV NEXLOG_WORKSPACE_DIR="/data/cases"
ENV NEXLOG_UPLOAD_DIR="/data/uploads"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=5)"

CMD ["python", "-m", "interface.web.serve", "--host", "0.0.0.0", "--port", "8000"]
