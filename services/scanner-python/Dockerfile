FROM python:3.12-slim

WORKDIR /opt/cti-scanner
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scanner_service ./scanner_service

ENV PYTHONUNBUFFERED=1
EXPOSE 9100
CMD ["uvicorn", "scanner_service.main:app", "--host", "0.0.0.0", "--port", "9100"]
