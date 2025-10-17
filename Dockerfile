# Dockerfile
FROM python:3.9-slim

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python packages
RUN pip install scapy pandas scikit-learn numpy xgboost netifaces

COPY . .

CMD ["python", "script.py"]