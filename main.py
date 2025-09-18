from flask import Flask, request
from telegram import Update
from config import FLASK_SECRET_KEY, WEBHOOK_URL, PORT, logger
from bot_handlers import main_bot, application, initialize_bot_and_app
import asyncio
import threading
from routes import register_routes

# Initialize Flask app
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Register routes
register_routes(app)

# Webhook route
@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        data = request.get_json(force=True)
        update = Update.de_json(data, main_bot)
        if update:
            asyncio.run_coroutine_threadsafe(application.process_update(update), loop)
        return 'OK'
    except Exception as e:
        logger.error(f"Error in webhook: {e}")
        return 'Internal Server Error', 500

# Create event loop for async operations
loop = asyncio.new_event_loop()
threading.Thread(target=loop.run_forever, daemon=True).start()

# Initialize bot and application
asyncio.run_coroutine_threadsafe(initialize_bot_and_app(), loop).result()

if __name__ == '__main__':
    try:
        asyncio.run_coroutine_threadsafe(main_bot.set_webhook(WEBHOOK_URL), loop).result()
        logger.info(f"Webhook set to {WEBHOOK_URL}")
    except Exception as e:
        logger.error(f"Failed to set webhook: {e}")
        exit(1)
    app.run(host='0.0.0.0', port=PORT)
    loop.call_soon_threadsafe(loop.stop)
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()

