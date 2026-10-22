# Concept: scanner als container, zodat hij bij de klant draait en de code het bedrijf niet verlaat.
# Bouwen:  docker build -t aiscan .
# Draaien: docker run --rm -v "$PWD":/code -v "$PWD/aiscan-rapport":/out aiscan /code --out /out --klant "Naam" --app "App"
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/aiscan
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY aiscan ./aiscan
RUN git config --global --add safe.directory '*'
ENTRYPOINT ["python", "-m", "aiscan"]
