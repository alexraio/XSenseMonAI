FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Create non-root user and state directory
RUN groupadd -r pfsensemon && useradd -r -g pfsensemon pfsensemon \
    && mkdir -p /app/state \
    && chown -R pfsensemon:pfsensemon /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
RUN chown -R pfsensemon:pfsensemon /app

USER pfsensemon

ENTRYPOINT ["python", "-m", "src.main"]
