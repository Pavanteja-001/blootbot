from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from gridfs import GridFS
from config import MONGODB_URI, logger
import random
import string

def init_db():
    try:
        client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000,
            retryWrites=True,
            retryReads=True,
            maxPoolSize=50
        )
        client.admin.command('ping')
        logger.info("Connected to MongoDB Atlas")
        db = client.bloodbot
        return {
            'client': client,
            'db': db,
            'users': db.users,
            'hospitals': db.hospitals,
            'otps': db.otps,
            'requests': db.requests,
            'fs': GridFS(db)
        }
    except ServerSelectionTimeoutError as e:
        logger.error(f"MongoDB connection failed: {e}")
        exit(1)

# Initialize database
db_resources = init_db()
mongo_client = db_resources['client']
db = db_resources['db']
users_collection = db_resources['users']
hospitals_collection = db_resources['hospitals']
otps_collection = db_resources['otps']
requests_collection = db_resources['requests']
fs = db_resources['fs']

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def get_user_by_phone(phone_number):
    """
    Retrieve a user from the users collection by phone number.
    Returns the user document or None if not found.
    """
    return db.users.find_one({"contact_number": phone_number})