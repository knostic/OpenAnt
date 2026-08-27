FROM python:3.11-slim
WORKDIR /test
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY test_exploit.py .
CMD ["python", "test_exploit.py"]
