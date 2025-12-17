FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Expose port
EXPOSE 5000

# Set Python to unbuffered mode for immediate log output
ENV PYTHONUNBUFFERED=1

# Run with hypercorn (ASGI server for async Flask)
# Use app:app (the module exports 'app' variable directly)
# Enable access and error logs to stdout
CMD ["hypercorn", "app:app", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--worker-class", "asyncio", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info"]