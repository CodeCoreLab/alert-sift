FROM python:3.11-slim
LABEL org.opencontainers.image.title="alert-sift"
LABEL org.opencontainers.image.description="Alert denoising gateway with AI-ops guard (MCP)"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY config ./config
COPY configs ./configs
RUN mkdir -p /app/data
EXPOSE 9999
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9999"]
