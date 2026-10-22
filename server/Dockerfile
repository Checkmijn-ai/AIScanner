# checkmijn.ai: website én API in één app (Flask + gunicorn).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 checkmijn
WORKDIR /app
COPY requirements-server.txt /tmp/requirements-server.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements-server.txt
COPY aiscan ./aiscan
COPY platform ./platform
COPY voorbeelden ./voorbeelden
COPY norm ./norm
RUN mkdir -p /data && chown checkmijn /data
USER checkmijn
ENV AISCAN_DB=/data/checkmijn.db \
    AISCAN_PUBLIC_URL=https://checkmijn-ai.github.io/AIScanner \
    AISCAN_SITE=https://api.checkmijn.ai \
    AISCAN_SITE_ORIGIN=https://checkmijn.ai \
    CHECKMIJN_NIEUWS=/data/nieuws.json
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/robots.txt',timeout=4)"
# één proces (de limiet per IP en SQLite zitten in het geheugen van dat proces), meerdere threads
CMD ["gunicorn", "--chdir", "/app/platform", "-w", "1", "--threads", "8", "-b", "0.0.0.0:8000", "--access-logfile", "-", "api:app"]
