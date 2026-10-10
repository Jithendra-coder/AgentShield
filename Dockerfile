FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system agentshield \
    && adduser --system --ingroup agentshield --home /app agentshield

COPY agentshield ./agentshield
USER agentshield
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"

CMD ["uvicorn", "agentshield.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
