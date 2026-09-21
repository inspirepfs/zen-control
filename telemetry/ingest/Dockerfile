FROM python:3.14.6-slim
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir "psycopg[binary]>=3.2,<4" dnspython==2.8.0
COPY ingest.py service_map.py ./
CMD ["python","-u","ingest.py"]
