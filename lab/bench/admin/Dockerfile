FROM python:3.11-slim
WORKDIR /srv
COPY admin.py .
RUN pip install --no-cache-dir flask==3.0.3
CMD ["python", "admin.py"]
