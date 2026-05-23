FROM python:3.11-slim

WORKDIR /app

# Устанавливаем инструменты безопасности
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip git \
    && rm -rf /var/lib/apt/lists/*

# subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip subfinder \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

# nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip \
    && unzip nuclei_3.2.9_linux_amd64.zip nuclei \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.2.9_linux_amd64.zip

# gitleaks
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    && tar -xzf gitleaks_8.18.4_linux_x64.tar.gz gitleaks \
    && mv gitleaks /usr/local/bin/ \
    && rm gitleaks_8.18.4_linux_x64.tar.gz

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app

CMD ["celery", "-A", "workers.celery_app", "worker", "--loglevel=info", "--concurrency=4"]
