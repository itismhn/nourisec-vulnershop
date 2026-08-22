FROM python:3.12-slim

# 'ping' binary is intentionally present - the admin health-check tool (a
# deliberate command-injection target, see app/admin.py) shells out to it.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p instance app/uploads && chmod +x docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["./docker-entrypoint.sh"]
