# Feedback collector — a SEPARATE container from the relay node.
# Build from the REPO ROOT (it needs src/limits.ts):
#   docker build -f feedback-collector/Dockerfile -t brainstorm-feedback .
#   docker run -p 7790:7790 -v feedback-data:/app/feedback-data \
#     -e FEEDBACK_GITHUB_REPO=owner/inbox -e FEEDBACK_GITHUB_TOKEN=... \
#     brainstorm-feedback
FROM oven/bun:1.3-slim
WORKDIR /app
COPY src ./src
COPY feedback-collector ./feedback-collector
ENV FEEDBACK_PORT=7790 \
    FEEDBACK_DATA_DIR=/app/feedback-data
EXPOSE 7790
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:'+(process.env.FEEDBACK_PORT||7790)+'/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["bun", "run", "feedback-collector/src/main.ts"]
