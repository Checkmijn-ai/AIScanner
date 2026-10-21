# checkmijn.ai: website én API in één app (Flask + gunicorn).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 checkmijn
WORKDIR /app
RUN pip install --no-cache-dir "flask>=3" "gunicorn>=22" "jinja2>=3.1" "pyyaml>=6" "cryptography>=42" "packaging>=23" "requests>=2.31"
COPY aiscan ./aiscan
COPY platform ./platform
COPY voorbeelden ./voorbeelden
RUN mkdir -p /data && chown checkmijn /data
USER checkmijn
ENV AISCAN_DB=/data/checkmijn.db \
    AISCAN_PUBLIC_URL=https://checkmijn-ai.github.io/AIScanner \
    AISCAN_SITE=https://api.checkmijn.ai \
    AISCAN_SITE_ORIGIN=https://checkmijn.ai
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/robots.txt',timeout=4)"
# één proces (de limiet per IP en SQLite zitten in het geheugen van dat proces), meerdere threads
CMD ["gunicorn", "--chdir", "/app/platform", "-w", "1", "--threads", "8", "-b", "0.0.0.0:8000", "--access-logfile", "-", "api:app"]
