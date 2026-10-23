FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && git clone --depth 1 https://github.com/alexbers/mtprotoproxy /app \
 && pip install --no-cache-dir cryptography segno \
 && apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY panel /panel
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# 3128-3137: public TCP entry ports (one per Railway TCP Proxy) | 8080: panel
EXPOSE 3128 8080
CMD ["python3", "/panel/panel.py"]
