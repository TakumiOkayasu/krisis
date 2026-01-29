FROM python:slim

WORKDIR /app

# Install test dependencies (cached layer)
RUN pip install --no-cache-dir pytest pytest-cov

# Copy source code
COPY src/ ./src/

# Copy tests
COPY tests/ ./tests/

ENV PYTHONPATH=/app/src

CMD ["pytest", "tests/", "-v"]
