FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV CASCADE_DATA_DIR=/data
EXPOSE 8777
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8777"]
