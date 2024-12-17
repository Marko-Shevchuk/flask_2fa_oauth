# Build stage
FROM python:3.11-slim AS builder
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
# Runtime stage
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /app .
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

EXPOSE 5000
ENV FLASK_APP=run.py
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]