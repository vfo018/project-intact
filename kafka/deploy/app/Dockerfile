FROM python:3.10.12

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all of the scripts
COPY . .

# Defaut mitigator
ENV MODE="mitigator"

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["python","-u","entrypoint.py"]
