import os
import asyncio
import threading
from flask import Flask, request
from telegram import Update
from telegram.error import TelegramError
from config import FLASK_SECRET_KEY, WEBHOOK_URL, logger
from bot_handlers import main_bot, application, initialize_bot_and_app
from routes import register_routes

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", FLASK_SECRET_KEY)

# Register routes
register_routes(app)

# Webhook route
@app.route('/webhook', methods=['POST'])
async def webhook():
    try:
        data = request.get_json(force=True)
        logger.debug(f"Received webhook data: {data}")
        update = Update.de_json(data, main_bot)
        if not update:
            logger.error("Failed to parse Telegram update")
            return 'Invalid update', 400
        await application.process_update(update)
        logger.debug(f"Processed update: {update.update_id}")
        return 'OK', 200
    except TelegramError as te:
        logger.error(f"Telegram error in webhook: {str(te)}", exc_info=True)
        return 'Telegram Error', 500
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}", exc_info=True)
        return 'Internal Server Error', 500

# Create event loop for async operations
loop = asyncio.new_event_loop()
threading.Thread(target=loop.run_forever, daemon=True).start()

# Initialize bot and application
try:
    asyncio.run_coroutine_threadsafe(initialize_bot_and_app(), loop).result()
    logger.info("Bot and application initialized")
except Exception as e:
    logger.error(f"Failed to initialize bot: {e}")
    exit(1)

if __name__ == '__main__':
    try:
        asyncio.run_coroutine_threadsafe(main_bot.set_webhook(WEBHOOK_URL), loop).result()
        logger.info(f"Webhook set to {WEBHOOK_URL}")
    except Exception as e:
        logger.error(f"Failed to set webhook: {e}")
        exit(1)
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
    loop.call_soon_threadsafe(loop.stop)
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()
