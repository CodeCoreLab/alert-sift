FROM python:3.11-slim
LABEL org.opencontainers.image.title="alert-sift"
LABEL org.opencontainers.image.description="Alert denoising gateway with AI-ops guard (MCP)"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# P2-6（2026-10-30）：当前行为是 `COPY app ./app`，把 app/test_pipeline.py
# （单元测试）也打进生产镜像 —— 增大体积与攻击面，且测试代码可能误触发
# 对生产 DB 的建表/写入。改法：改用更精确的 COPY（只拷运行期需要的子目录与模块），
# 并配合仓库根的 .dockerignore 排除测试文件与缓存。
# 注意：app/test_pipeline.py 仍保留在仓库里（ci.yml 用它跑测试），只是不进镜像。
COPY app/*.py ./app/
COPY app/pipeline ./app/pipeline
COPY app/store ./app/store
COPY app/templates ./app/templates
COPY config ./config
COPY configs ./configs
RUN mkdir -p /app/data
EXPOSE 9999
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9999"]
