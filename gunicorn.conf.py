import os

# Bind to Render's PORT environment variable
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
workers = 1
threads = 4
timeout = 120
worker_class = "gthread"
