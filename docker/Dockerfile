FROM python:3.11-slim

LABEL maintainer="TopoChain Security Team"
LABEL description="Topological Invariant Drift Detection for Software Supply Chain Integrity"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY topochain /app/topochain

RUN pip install --upgrade pip && \
    pip install -e .

EXPOSE 8000

ENTRYPOINT ["topochain"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
