FROM python:3.12-slim
WORKDIR /app
COPY modbus_proxy.py .
USER nobody
CMD ["python3", "modbus_proxy.py"]
