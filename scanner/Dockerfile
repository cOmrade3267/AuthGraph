FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scanner.py .
COPY rules/ ./rules/
ENTRYPOINT ["python3", "scanner.py"]
