import os
from urllib.parse import quote_plus
from dotenv import load_dotenv
import logging
import random
import string

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress pymongo debug logs
logging.getLogger('pymongo').setLevel(logging.INFO)

# Load environment variables
load_dotenv()

# Telegram bot tokens
BOT_TOKEN = os.getenv("BOT_TOKEN")
OTP_BOT_TOKEN = os.getenv("OTP_BOT_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
PORT = int(os.getenv("PORT", 3000))

# Twilio credentials
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

# MongoDB credentials
MONGO_USERNAME = os.getenv("MONGO_USERNAME", "5221411062_db")
MONGO_PASSWORD = os.getenv("MONGO_PASSWORD", "Pavan@9182")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "bloodbot")
MONGO_SRV = os.getenv("MONGO_SRV", "true").lower() == "true"
MONGO_CLUSTER_URL = os.getenv("MONGO_CLUSTER_URL", "cluster0.pq8jnkl.mongodb.net")
MONGO_HOSTS = os.getenv("MONGO_HOSTS", "ac-xrksbem-shard-00-00.pq8jnkl.mongodb.net:27017,ac-xrksbem-shard-00-01.pq8jnkl.mongodb.net:27017,ac-xrksbem-shard-00-02.pq8jnkl.mongodb.net:27017")

# Encode MongoDB username and password
encoded_username = quote_plus(MONGO_USERNAME)
encoded_password = quote_plus(MONGO_PASSWORD)
MONGODB_URI = (f"mongodb+srv://{encoded_username}:{encoded_password}@{MONGO_CLUSTER_URL}/{MONGO_DB_NAME}?retryWrites=true&w=majority"
               if MONGO_SRV else
               f"mongodb://{encoded_username}:{encoded_password}@{MONGO_HOSTS}/{MONGO_DB_NAME}?retryWrites=true&w=majority&ssl=true")

# Flask secret key
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", ''.join(random.choices(string.ascii_letters + string.digits, k=32)))

# Admin password
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Validate critical environment variables
if not all([BOT_TOKEN, OTP_BOT_TOKEN, WEBHOOK_URL, MONGO_USERNAME, MONGO_PASSWORD]):
    logger.error("Missing critical environment variables")
    exit(1)

if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
    logger.warning("Missing Twilio credentials; SMS OTP delivery will fall back to Telegram")

# Constants
VALID_BLOOD_GROUPS = {'A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'}
VALID_URGENCIES = {'EMERGENCY', 'SCHEDULED', 'NORMAL'}
OTP_EXPIRY_MINUTES = 5
MAX_OTP_ATTEMPTS = 3