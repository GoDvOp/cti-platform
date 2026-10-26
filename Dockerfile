FROM python:3.13-slim@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY app ./app
COPY config ./config
COPY examples ./examples
COPY scripts ./scripts
COPY evaluation ./evaluation
COPY tests ./tests
COPY docs/cases ./docs/cases
COPY pyproject.toml .env.example start-cti.sh ./
# Keep the public snapshot outside /app/data, which is mounted at runtime.
COPY data/review_snapshot.json.gz data/submission_manifest.json ./bundle/
RUN mkdir -p /app/data && chmod -R a+rX /app && chown -R appuser:appuser /app
USER appuser
ENTRYPOINT ["python", "-m", "app.container"]
CMD ["status"]
