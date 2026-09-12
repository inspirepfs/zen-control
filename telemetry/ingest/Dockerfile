FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "psycopg[binary]>=3.2,<4" dnspython==2.8.0
COPY ingest.py service_map.py ./
CMD ["python","-u","ingest.py"]
