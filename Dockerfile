FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p logs/reports malware/quarantine ml_engine/models

EXPOSE 22 80 21 23 3306 6379 25 3389 445 27017 9200 5900 5000

CMD ["python3", "main.py"]
