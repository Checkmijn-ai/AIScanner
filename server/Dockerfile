# API van checkmijn.ai: sessiecodes, controle van bewijsbestanden, scorepagina's en badges.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 checkmijn
WORKDIR /app
RUN pip install --no-cache-dir "flask>=3" "gunicorn>=22" "jinja2>=3.1" "pyyaml>=6" "cryptography>=42" "packaging>=23" "requests>=2.31"
COPY aiscan ./aiscan
COPY platform ./platform
RUN mkdir -p /data && chown checkmijn /data
USER checkmijn
ENV AISCAN_DB=/data/checkmijn.db \
    AISCAN_PUBLIC_URL=https://checkmijn-ai.github.io/AIScanner \
    AISCAN_SITE=https://api.checkmijn.ai
EXPOSE 8000
# één proces (de limiet per IP en SQLite zitten in het geheugen van dat proces), meerdere threads
CMD ["gunicorn", "--chdir", "/app/platform", "-w", "1", "--threads", "8", "-b", "0.0.0.0:8000", "--access-logfile", "-", "api:app"]
