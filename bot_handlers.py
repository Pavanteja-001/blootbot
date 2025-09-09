import asyncio
import re
from datetime import datetime, timedelta
from telegram import Bot, Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from telegram.error import BadRequest
from config import BOT_TOKEN, OTP_BOT_TOKEN, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER, VALID_BLOOD_GROUPS, VALID_URGENCIES, OTP_EXPIRY_MINUTES, MAX_OTP_ATTEMPTS, logger
from db_utils import users_collection, otps_collection, requests_collection, hospitals_collection, fs
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import random
import string
import bcrypt
from bson import ObjectId

# Initialize Twilio client
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN else None

# Initialize bots
main_bot = Bot(token=BOT_TOKEN)
otp_bot = Bot(token=OTP_BOT_TOKEN)
application = Application.builder().token(BOT_TOKEN).connection_pool_size(100).pool_timeout(60).build()

# Conversation state (consider Redis for production)
conversation_state = {}

# Generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Clean expired OTPs
def clean_expired_otps():
    try:
        current_time = datetime.now()
        otps_collection.delete_many({"expires": {"$lt": current_time}})
        logger.debug("Cleaned expired OTPs from MongoDB")
    except Exception as e:
        logger.error(f"Error cleaning expired OTPs: {e}")

# Validate phone number
def is_valid_phone_number(phone):
    return bool(re.match(r'^\+?\d{10,15}$', phone))

# Hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Verify password
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# /start command
async def start(update: Update, context):
    chat_id = update.effective_chat.id
    logger.info(f"Executing /start handler for chat_id: {chat_id}")
    try:
        await context.bot.send_message(
            chat_id=chat_id,
            text="👋 Welcome to BloodBot! Are you a donor or a patient? Type 'Donor' or 'Patient'."
        )
        conversation_state[chat_id] = {'state': 'waiting_for_role'}
        logger.debug(f"Set state to waiting_for_role for chat_id: {chat_id}")
    except Exception as e:
        logger.error(f"Error in /start handler for chat_id {chat_id}: {e}", exc_info=True)
        await context.bot.send_message(
            chat_id=chat_id,
            text="An error occurred. Please try again."
        )

# Handle text messages and images
async def handle_message(update: Update, context):
    chat_id = update.effective_chat.id
    text = update.message.text.strip() if update.message.text else ''
    logger.info(f"Handling message for chat_id: {chat_id}, text: {text}")

    state = conversation_state.get(chat_id, {}).get('state', '')
    text_upper = text.upper() if text else ''

    # Handle donor accept/reject commands (e.g., 'accept <request_id>')
    if text_upper.startswith('ACCEPT ') or text_upper.startswith('REJECT '):
        try:
            command, req_id = text.split(' ', 1)
            request = requests_collection.find_one({'_id': ObjectId(req_id), 'status': 'approved'})
            if not request:
                await context.bot.send_message(chat_id=chat_id, text="Invalid or non-approved request ID.")
                return
            user = users_collection.find_one({'chat_id': chat_id, 'role': 'DONOR'})
            if not user or user['blood_group'] != request['blood_group'] or user['city'] != request['city']:
                await context.bot.send_message(chat_id=chat_id, text="You are not eligible for this request.")
                return
            if request.get('status') == 'accepted':
                await context.bot.send_message(chat_id=chat_id, text="This request has already been accepted by another donor.")
                return
            if command.upper() == 'REJECT':
                await context.bot.send_message(chat_id=chat_id, text="Request rejected. Thank you for considering.")
                return
            # Accept the request
            requests_collection.update_one(
                {'_id': ObjectId(req_id)},
                {'$set': {'status': 'accepted', 'accepted_by_donor_id': user['_id']}}
            )
            patient = users_collection.find_one({'chat_id': request['patient_chat_id']})
            # Send donor details to patient
            await main_bot.send_message(
                chat_id=request['patient_chat_id'],
                text=f"Your request {req_id} has been accepted by donor {user['name']} ({user['blood_group']}). Contact: {user['contact_number']}, Address: {user['address']}, {user['city']}. Please provide a review after donation by typing 'review {chat_id} <rating 1-5> <comment>'."
            )
            # Notify donor
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"You have accepted request {req_id}. Contact patient {patient['name']} at {patient['contact_number']}."
            )
            # Notify other donors
            for other_donor in users_collection.find({
                'role': 'DONOR',
                'blood_group': request['blood_group'],
                'city': request['city'],
                'verified': True,
                '_id': {'$ne': user['_id']}
            }):
                await main_bot.send_message(
                    chat_id=other_donor['chat_id'],
                    text=f"Request {req_id} has been accepted by another donor. Thank you for your availability."
                )
        except Exception as e:
            logger.error(f"Error handling accept/reject for chat_id {chat_id}: {e}")
            await context.bot.send_message(chat_id=chat_id, text="An error occurred. Please try again.")
        return

    # Handle patient review commands (e.g., 'review <donor_chat_id> <rating> <comment>')
    if text_upper.startswith('REVIEW '):
        try:
            _, donor_chat_id_str, rating_str, *comment_parts = text.split(' ')
            donor_chat_id = int(donor_chat_id_str)
            rating = int(rating_str)
            comment = ' '.join(comment_parts)
            if rating < 1 or rating > 5:
                await context.bot.send_message(chat_id=chat_id, text="Rating must be between 1 and 5.")
                return
            donor = users_collection.find_one({'chat_id': donor_chat_id, 'role': 'DONOR'})
            if not donor:
                await context.bot.send_message(chat_id=chat_id, text="Invalid donor ID.")
                return
            # Add review to donor profile
            users_collection.update_one(
                {'_id': donor['_id']},
                {'$push': {'reviews': {'rating': rating, 'comment': comment, 'from_chat_id': chat_id, 'date': datetime.now()}}}
            )
            await context.bot.send_message(chat_id=chat_id, text="Thank you for your review!")
            # Notify donor of review
            await main_bot.send_message(
                chat_id=donor_chat_id,
                text=f"You received a review: {rating}/5 - {comment}"
            )
        except ValueError:
            await context.bot.send_message(chat_id=chat_id, text="Invalid format. Use 'review <donor_chat_id> <rating 1-5> <comment>'.")
        except Exception as e:
            logger.error(f"Error handling review for chat_id {chat_id}: {e}")
            await context.bot.send_message(chat_id=chat_id, text="An error occurred. Please try again.")
        return

    # Handle image uploads
    if update.message.photo:
        try:
            photo = update.message.photo[-1]
            file = await photo.get_file()
            file_data = await file.download_as_bytearray()
            file_id = fs.put(file_data, filename=f"{chat_id}_image.jpg")
            users_collection.update_one(
                {'chat_id': chat_id},
                {'$set': {'image_file_id': str(file_id)}}
            )
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Image uploaded successfully! You can continue with the registration."
            )
        except Exception as e:
            logger.error(f"Error handling image for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="Error uploading image. Please try again."
            )
        return

    # Handle role input
    if state == 'waiting_for_role':
        if text_upper not in {'DONOR', 'PATIENT'}:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type 'Donor' or 'Patient'."
            )
            return
        try:
            clean_expired_otps()
            conversation_state[chat_id] = {'state': 'waiting_for_phone_number', 'role': text_upper}
            await context.bot.send_message(
                chat_id=chat_id,
                text="📱 Please type your phone number (e.g., +911234567890 or 1234567890). OTP will be sent to this number."
            )
        except Exception as e:
            logger.error(f"Error in role handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle phone number input
    if state == 'waiting_for_phone_number':
        if not is_valid_phone_number(text):
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid phone number (e.g., +911234567890 or 1234567890, 10-15 digits)."
            )
            return
        try:
            phone_number = text if text.startswith('+') else f"+91{text}"
            if users_collection.find_one({'contact_number': phone_number}):
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="This phone number is already registered. Please use a different number or login via dashboard."
                )
                conversation_state[chat_id] = {'state': 'waiting_for_role'}
                return
            conversation_state[chat_id]['phone_number'] = phone_number
            otp = generate_otp()
            otps_collection.insert_one({
                'chat_id': chat_id,
                'otp': otp,
                'expires': datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES),
                'attempts': 0
            })
            sms_sent = False
            if twilio_client:
                try:
                    twilio_client.messages.create(
                        body=f"Your BloodBot OTP is: {otp}. Please type this OTP in @blooodbanktest. OTP expires in 5 minutes.",
                        from_=TWILIO_PHONE_NUMBER,
                        to=phone_number
                    )
                    sms_sent = True
                except TwilioRestException as e:
                    logger.error(f"Failed to send SMS to {phone_number}: {e}")
            if not sms_sent:
                try:
                    await otp_bot.send_message(
                        chat_id=chat_id,
                        text=f"Your OTP is: {otp}\nPlease type this OTP in @blooodbanktest. OTP expires in 5 minutes."
                    )
                except BadRequest as e:
                    if "chat not found" in str(e).lower():
                        await context.bot.send_message(
                            chat_id=chat_id,
                            text="Unable to send SMS and you haven't started a chat with @Verifybloodbankotp_bot. Please type /start in @Verifybloodbankotp_bot and enter your phone number here again."
                        )
                        otps_collection.delete_one({'chat_id': chat_id})
                        return
                    elif "bot was blocked by the user" in str(e).lower():
                        await context.bot.send_message(
                            chat_id=chat_id,
                            text="Unable to send OTP because you have blocked @Verifybloodbankotp_bot. Please unblock the bot, send /start to @Verifybloodbankotp_bot, and enter your phone number here again."
                        )
                        otps_collection.delete_one({'chat_id': chat_id})
                        return
                    raise e
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"✅ OTP has been sent to your phone number{' or from @Verifybloodbankotp_bot' if not sms_sent else ''}. Please type the OTP here."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_otp'
        except Exception as e:
            logger.error(f"Error in phone number handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
            otps_collection.delete_one({'chat_id': chat_id})
        return

    # Handle OTP input
    if state == 'waiting_for_otp':
        clean_expired_otps()
        otp_data = otps_collection.find_one({'chat_id': chat_id})
        if not otp_data:
            await context.bot.send_message(
                chat_id=chat_id,
                text="OTP expired or not found. Please type 'Donor' or 'Patient' again."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_role'
            return
        otps_collection.update_one({'chat_id': chat_id}, {'$inc': {'attempts': 1}})
        if otp_data['attempts'] + 1 > MAX_OTP_ATTEMPTS:
            otps_collection.delete_one({'chat_id': chat_id})
            await context.bot.send_message(
                chat_id=chat_id,
                text="Maximum OTP attempts exceeded. Please type 'Donor' or 'Patient' again."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_role'
            return
        if text != otp_data['otp']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"Invalid OTP. Try again ({MAX_OTP_ATTEMPTS - otp_data['attempts'] - 1} attempts remaining)."
            )
            return
        try:
            otps_collection.delete_one({'chat_id': chat_id})
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ OTP verified! Please set a password for your dashboard login (minimum 6 characters)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_password'
        except Exception as e:
            logger.error(f"Error in OTP handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle password input
    if state == 'waiting_for_password':
        if len(text) < 6:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Password must be at least 6 characters long. Please try again."
            )
            return
        try:
            role = conversation_state[chat_id]['role']
            phone_number = conversation_state[chat_id]['phone_number']
            user_data = {
                'chat_id': chat_id,
                'role': role,
                'contact_number': phone_number,
                'password_hash': hash_password(text),
                'blood_group': '',
                'image_file_id': None,
                'verified': False,
                'reviews': []  # Initialize reviews array
            }
            if role == 'DONOR':
                user_data.update({
                    'name': '',
                    'address': '',
                    'city': '',
                    'district': '',
                    'state': '',
                    'age': 0,
                    'weight': 0.0,
                    'health_condition': '',
                    'last_donation_date': '',
                    'donation_count': 0
                })
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="✅ Password set! Please type your full name (e.g., John Doe)."
                )
                conversation_state[chat_id]['state'] = 'waiting_for_donor_name'
            else:
                user_data.update({
                    'name': '',
                    'hospital_name': '',
                    'city': '',
                    'district': '',
                    'state': ''
                })
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="✅ Password set! Please type your name (e.g., Jane Smith)."
                )
                conversation_state[chat_id]['state'] = 'waiting_for_patient_name'
            users_collection.insert_one(user_data)
            await context.bot.send_message(
                chat_id=chat_id,
                text="You can log in to your dashboard at: https://9823e9954863.ngrok-free.app/login"
            )
        except Exception as e:
            logger.error(f"Error in password handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor name
    if state == 'waiting_for_donor_name':
        if not text or text.startswith('/'):
            await context.bot.send_message(chat_id=chat_id, text="Please type a valid name.")
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'name': text}})
            await context.bot.send_message(chat_id=chat_id, text="✅ Got it! Now type your address (e.g., 123 Main St).")
            conversation_state[chat_id]['state'] = 'waiting_for_donor_address'
        except Exception as e:
            logger.error(f"Error in donor name handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(chat_id=chat_id, text="An error occurred. Please try again.")
        return

    # Handle donor address
    if state == 'waiting_for_donor_address':
        if not text or text.startswith('/'):
            await context.bot.send_message(chat_id=chat_id, text="Please type a valid address.")
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'address': text}})
            await context.bot.send_message(chat_id=chat_id, text="✅ Got it! Now type your city (e.g., Hyderabad).")
            conversation_state[chat_id]['state'] = 'waiting_for_donor_city'
        except Exception as e:
            logger.error(f"Error in donor address handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor city
    if state == 'waiting_for_donor_city':
        if not text or text.startswith('/'):
            await context.bot.send_message(chat_id=chat_id, text="Please type a valid city.")
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'city': text}})
            await context.bot.send_message(chat_id=chat_id, text="✅ Got it! Now type your district (e.g., Ranga Reddy).")
            conversation_state[chat_id]['state'] = 'waiting_for_donor_district'
        except Exception as e:
            logger.error(f"Error in donor city handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor district
    if state == 'waiting_for_donor_district':
        if not text or text.startswith('/'):
            await context.bot.send_message(chat_id=chat_id, text="Please type a valid district.")
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'district': text}})
            await context.bot.send_message(chat_id=chat_id, text="✅ Got it! Now type your state (e.g., Telangana).")
            conversation_state[chat_id]['state'] = 'waiting_for_donor_state'
        except Exception as e:
            logger.error(f"Error in donor district handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor state
    if state == 'waiting_for_donor_state':
        if not text or text.startswith('/'):
            await context.bot.send_message(chat_id=chat_id, text="Please type a valid state.")
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'state': text}})
            await context.bot.send_message(chat_id=chat_id, text="✅ Got it! Now type your age (e.g., 30).")
            conversation_state[chat_id]['state'] = 'waiting_for_donor_age'
        except Exception as e:
            logger.error(f"Error in donor state handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor age
    if state == 'waiting_for_donor_age':
        try:
            age = int(text)
            if age < 18 or age > 65:
                await context.bot.send_message(chat_id=chat_id, text="Age must be between 18 and 65.")
                return
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'age': age}})
            await context.bot.send_message(chat_id=chat_id, text="✅ Got it! Now type your weight in kg (e.g., 70).")
            conversation_state[chat_id]['state'] = 'waiting_for_donor_weight'
        except ValueError:
            await context.bot.send_message(chat_id=chat_id, text="Please type a valid number for age.")
        except Exception as e:
            logger.error(f"Error in donor age handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor weight
    if state == 'waiting_for_donor_weight':
        try:
            weight = float(text)
            if weight < 50:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="Weight must be at least 50 kg."
                )
                return
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'weight': weight}})
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type any health conditions (e.g., None or Diabetes)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_donor_health'
        except ValueError:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid number for weight."
            )
        except Exception as e:
            logger.error(f"Error in donor weight handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor health condition
    if state == 'waiting_for_donor_health':
        if not text or text.startswith('/'):
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid health condition or 'None'."
            )
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'health_condition': text}})
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type your blood group (e.g., A+, B-, O+)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_donor_blood_group'
        except Exception as e:
            logger.error(f"Error in donor health handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor blood group
    if state == 'waiting_for_donor_blood_group':
        if text_upper not in VALID_BLOOD_GROUPS:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid blood group (e.g., A+, B-, O+)."
            )
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'blood_group': text_upper}})
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type the date of your last donation (YYYY-MM-DD or 'None')."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_donor_last_donation'
        except Exception as e:
            logger.error(f"Error in donor blood group handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor last donation
    if state == 'waiting_for_donor_last_donation':
        if text_upper != 'NONE':
            try:
                datetime.strptime(text, '%Y-%m-%d')
            except ValueError:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="Please type a valid date (YYYY-MM-DD) or 'None'."
                )
                return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'last_donation_date': text}})
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type the number of times you have donated blood (e.g., 5)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_donor_count'
        except Exception as e:
            logger.error(f"Error in donor last donation handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle donor donation count
    if state == 'waiting_for_donor_count':
        try:
            count = int(text)
            if count < 0:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="Donation count cannot be negative."
                )
                return
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'donation_count': count}})
            await context.bot.send_message(
                chat_id=chat_id,
                text="🎉 Thank you, Donor! Your profile has been registered. You can upload an image if needed. Please wait for hospital verification."
            )
            conversation_state[chat_id]['state'] = ''
        except ValueError:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid number for donation count."
            )
        except Exception as e:
            logger.error(f"Error in donor count handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle patient name
    if state == 'waiting_for_patient_name':
        if not text or text.startswith('/'):
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid name."
            )
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'name': text}})
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type the hospital name (e.g., Apollo Hospital). It must be a registered hospital."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_patient_hospital'
        except Exception as e:
            logger.error(f"Error in patient name handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle patient hospital
    if state == 'waiting_for_patient_hospital':
        if not text or text.startswith('/'):
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid hospital name."
            )
            return
        try:
            hospital = hospitals_collection.find_one({'name': {'$regex': f'^{text}$', '$options': 'i'}})
            if not hospital:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="Hospital not found. Please type a registered hospital name."
                )
                return
            # Use exact DB name for consistency
            exact_hospital_name = hospital['name']
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'hospital_name': exact_hospital_name}})
            # If matched, set location from hospital and skip to blood group
            users_collection.update_one({'chat_id': chat_id}, {'$set': {
                'city': hospital['city'],
                'district': hospital['district'],
                'state': hospital['state']
            }})
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Hospital matched! Using stored location. Now type your blood group (e.g., A+, B-, O+)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_patient_blood_group'
        except Exception as e:
            logger.error(f"Error in patient hospital handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle patient blood group
    if state == 'waiting_for_patient_blood_group':
        if text_upper not in VALID_BLOOD_GROUPS:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid blood group (e.g., A+, B-, O+)."
            )
            return
        try:
            users_collection.update_one({'chat_id': chat_id}, {'$set': {'blood_group': text_upper}})
            hospital = hospitals_collection.find_one({'name': users_collection.find_one({'chat_id': chat_id})['hospital_name']})
            if hospital and hospital.get('blood_inventory', {}).get(text_upper, 0) > 0:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=f"✅ The hospital {hospital['name']} has {hospital['blood_inventory'][text_upper]} units of {text_upper} blood in stock. Contact the hospital for further details."
                )
                conversation_state[chat_id]['state'] = ''
                return
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type the number of units needed (e.g., 2)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_patient_units'
        except Exception as e:
            logger.error(f"Error in patient blood group handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle patient units
    if state == 'waiting_for_patient_units':
        try:
            units = int(text)
            if units <= 0:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="Number of units must be positive."
                )
                return
            conversation_state[chat_id]['units_needed'] = units
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type the urgency level (EMERGENCY, SCHEDULED, NORMAL)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_patient_urgency'
        except ValueError:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid number for units needed."
            )
        except Exception as e:
            logger.error(f"Error in patient units handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle patient urgency
    if state == 'waiting_for_patient_urgency':
        if text_upper not in VALID_URGENCIES:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid urgency level (EMERGENCY, SCHEDULED, NORMAL)."
            )
            return
        try:
            conversation_state[chat_id]['urgency'] = text_upper
            await context.bot.send_message(
                chat_id=chat_id,
                text="✅ Got it! Now type the time needed (YYYY-MM-DD HH:MM, e.g., 2025-09-10 14:00)."
            )
            conversation_state[chat_id]['state'] = 'waiting_for_patient_time'
        except Exception as e:
            logger.error(f"Error in patient urgency handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    # Handle patient time and create request
    if state == 'waiting_for_patient_time':
        try:
            time_needed = datetime.strptime(text, '%Y-%m-%d %H:%M')
            if time_needed < datetime.now():
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="Time needed must be today or in the future. Please enter a valid date and time (YYYY-MM-DD HH:MM)."
                )
                return
            user = users_collection.find_one({'chat_id': chat_id})
            request_data = {
                'patient_chat_id': chat_id,
                'hospital_name': user['hospital_name'],
                'blood_group': user['blood_group'],
                'units_needed': conversation_state[chat_id]['units_needed'],
                'urgency': conversation_state[chat_id]['urgency'],
                'time_needed': text,
                'city': user['city'],
                'district': user['district'],
                'state': user['state'],
                'status': 'pending',
                'approved_by_hospital': False,
                'created_at': datetime.now()
            }
            request_id = requests_collection.insert_one(request_data).inserted_id
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"🎉 Thank you, Patient! Your blood request has been submitted to {user['hospital_name']} for approval. You will be notified once approved."
            )
            conversation_state[chat_id]['state'] = ''
        except ValueError:
            await context.bot.send_message(
                chat_id=chat_id,
                text="Please type a valid date and time (YYYY-MM-DD HH:MM)."
            )
        except Exception as e:
            logger.error(f"Error in patient time handler for chat_id {chat_id}: {e}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="An error occurred. Please try again."
            )
        return

    await context.bot.send_message(
        chat_id=chat_id,
        text="Please start with /start."
    )

# Register handlers
application.add_handler(CommandHandler('start', start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND | filters.PHOTO, handle_message))

# Initialize bot and application
async def initialize_bot_and_app():
    try:
        await main_bot.initialize()
        await otp_bot.initialize()
        await application.initialize()
        logger.info("Main bot, OTP bot, and Application initialized")
    except Exception as e:
        logger.error(f"Error initializing bot and application: {e}")
        exit(1)