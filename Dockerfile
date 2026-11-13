FROM python:3.12-slim

# nftables 用户态工具；精简镜像里需要手动安装
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app

# 数据目录（SQLite 持久化卷挂载点）
RUN mkdir -p /data
VOLUME ["/data"]

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 8090
ENTRYPOINT ["/entrypoint.sh"]
