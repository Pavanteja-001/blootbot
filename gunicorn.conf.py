
import os

# Bind to Render's PORT environment variable
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
workers = 1  # Single worker for free tier
threads = 4  # Handle async Telegram requests
timeout = 120  # Match bot_handlers.py pool_timeout
