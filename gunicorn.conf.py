# File: gunicorn.conf.py

import os

# --- Server Socket ---
# Bind to 0.0.0.0 to be accessible from outside (e.g., in a container)
# Use the PORT environment variable if available, otherwise default to 5000
bind = os.getenv('GUNICORN_BIND', f"127.0.0.1:{os.getenv('PORT', '5000')}")

# --- Worker Processes ---
# Run multiple workers to handle requests concurrently.
# This is the key to high availability.
# (2 * num_cpus) + 1 is a common recommendation.
workers = int(os.getenv('GUNICORN_WORKERS', (os.cpu_count() * 2) + 1))

# --- Worker Class ---
# 'sync' is the default, but 'gthread' can be used for threaded apps.
worker_class = os.getenv('GUNICORN_WORKER_CLASS', 'sync')

# --- Logging ---
# Log to stdout and stderr so logs can be captured by a container or systemd
accesslog = '-'
errorlog = '-'

# --- Process Naming ---
# Makes 'ps' and 'top' more informative
proc_name = 'api-rate-limiter'

print(f"Starting Gunicorn with {workers} workers on {bind}")