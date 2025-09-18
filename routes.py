# --- START OF FILE routes.py ---

from flask import Flask, request, render_template, jsonify, session, redirect, url_for, send_file
from config import VALID_BLOOD_GROUPS, ADMIN_PASSWORD, logger
from db_utils import users_collection, hospitals_collection, requests_collection, fs, get_user_by_phone
from bson import ObjectId
import bcrypt
import io
import asyncio
from bot_handlers import application  # Import application for bot reuse
from telegram.error import TelegramError
import cloudinary
import cloudinary.uploader
import cloudinary.api
cloudinary.config(
    cloud_name='dettikmoj',
    api_key='638815394918313',
    api_secret='AV6vTtwKKwX3F7h9hzsI--S9OS8'
)
import time

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.salt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

async def send_message_with_retry(bot, chat_id, text, max_retries=3, delay=1):
    """Send a Telegram message with retry logic."""
    for attempt in range(max_retries):
        try:
            await bot.send_message(chat_id=chat_id, text=text)
            return True
        except TelegramError as e:
            logger.error(f"Attempt {attempt + 1}/{max_retries} failed for chat_id {chat_id}: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(delay * (2 ** attempt))  # Exponential backoff
            continue
    return False

def register_routes(app):
    @app.route('/')
    def home():
        return render_template('index.html')

    @app.route('/hospital/register', methods=['GET', 'POST'])
    def hospital_register():
        if request.method == 'POST':
            try:
                data = request.form
                registration_number = data.get('registration_number')
                name = data.get('name')
                address = data.get('address')
                city = data.get('city')
                district = data.get('district')
                state = data.get('state')
                latitude = data.get('latitude')
                longitude = data.get('longitude')
                password = data.get('password')

                blood_inventory = {bg: int(data.get(bg, 0)) for bg in VALID_BLOOD_GROUPS}

                if not all([registration_number, name, address, city, district, state, latitude, longitude, password]):
                    return jsonify({'error': 'All fields including GPS location are required'}), 400

                if len(password) < 6:
                    return jsonify({'error': 'Password must be at least 6 characters long'}), 400

                if hospitals_collection.find_one({'registration_number': registration_number}):
                    return jsonify({'error': 'Registration number already exists'}), 400

                # ---------------- Cloudinary Uploads ----------------
                license_file = request.files.get('license_certificate')
                license_url = None
                if license_file:
                    upload_result = cloudinary.uploader.upload(license_file, folder="hospital_license")
                    license_url = upload_result.get('secure_url')

                hospital_photo_file = request.files.get('hospital_photo')
                hospital_photo_url = None
                if hospital_photo_file:
                    upload_result = cloudinary.uploader.upload(hospital_photo_file, folder="hospital_photos")
                    hospital_photo_url = upload_result.get('secure_url')

                hospitals_collection.insert_one({
                    'registration_number': registration_number,
                    'name': name,
                    'address': address,
                    'city': city,
                    'district': district,
                    'state': state,
                    'latitude': latitude,
                    'longitude': longitude,
                    'password_hash': hash_password(password),
                    'blood_inventory': blood_inventory,
                    'license_url': license_url,
                    'hospital_photo_url': hospital_photo_url
                })
                return jsonify({'message': 'Hospital registered successfully'}), 200

            except Exception as e:
                logger.error(f"Error in hospital registration: {e}", exc_info=True)
                return jsonify({'error': 'An error occurred during registration'}), 500

        # For GET requests
        return render_template('hospital_register.html')
    @app.route('/hospital/login', methods=['GET', 'POST'])
    def hospital_login():
        if request.method == 'POST':
            try:
                registration_number = request.form.get('registration_number')
                password = request.form.get('password')
                hospital = hospitals_collection.find_one({'registration_number': registration_number})
                if hospital and verify_password(password, hospital['password_hash']):
                    session['hospital_id'] = str(hospital['_id'])
                    return redirect(url_for('hospital_dashboard'))
                return jsonify({'error': 'Invalid registration number or password'}), 401
            except Exception as e:
                logger.error(f"Error in hospital login: {e}")
                return jsonify({'error': 'An error occurred during login'}), 500
        return render_template('hospital_login.html')
    @app.route('/hospital/dashboard', methods=['GET', 'POST'])
    def hospital_dashboard():
            if 'hospital_id' not in session:
                return redirect(url_for('hospital_login'))
            try:
                hospital = hospitals_collection.find_one({'_id': ObjectId(session['hospital_id'])})
                if not hospital:
                    session.pop('hospital_id', None)
                    return redirect(url_for('hospital_login'))

                requests = list(requests_collection.find({'hospital_name': hospital['name']}))
                enriched_requests = []
                for req in requests:
                    patient = users_collection.find_one({'chat_id': req['patient_chat_id']})
                    if patient:
                        req['patient_name'] = patient['name']
                        req['patient_contact'] = patient['contact_number']
                    else:
                        req['patient_name'] = 'Unknown'
                        req['patient_contact'] = 'N/A'
                    enriched_requests.append(req)

                donors = list(users_collection.find({'role': 'DONOR', 'city': hospital['city'], 'verified': False}))

                if request.method == 'POST':
                    data = request.form
                    files = request.files

                    update_data = {
                        'name': data.get('name'),
                        'address': data.get('address'),
                        'city': data.get('city'),
                        'district': data.get('district'),
                        'state': data.get('state'),
                        'latitude': data.get('latitude'),
                        'longitude': data.get('longitude'),
                        'blood_inventory': {
                            blood_group: int(data.get(blood_group, 0)) for blood_group in VALID_BLOOD_GROUPS
                        }
                    }

                    # ✅ Upload hospital license to Cloudinary
                    if 'hospital_license' in files and files['hospital_license'].filename:
                        upload_result = cloudinary.uploader.upload(files['hospital_license'])
                        update_data['hospital_license_url'] = upload_result['secure_url']

                    # ✅ Upload hospital photo to Cloudinary
                    if 'hospital_photo' in files and files['hospital_photo'].filename:
                        upload_result = cloudinary.uploader.upload(files['hospital_photo'])
                        update_data['hospital_photo_url'] = upload_result['secure_url']

                    if not all([update_data['name'], update_data['address'], update_data['city'],
                                update_data['district'], update_data['state'],
                                update_data['latitude'], update_data['longitude']]):
                        return jsonify({'error': 'All fields including GPS location are required'}), 400

                    hospitals_collection.update_one(
                        {'_id': ObjectId(session['hospital_id'])},
                        {'$set': update_data}
                    )
                    return jsonify({'message': 'Details updated successfully'}), 200

                return render_template('hospital_dashboard.html',
                                    hospital=hospital,
                                    requests=enriched_requests,
                                    donors=donors)

            except Exception as e:
                logger.error(f"Error in hospital dashboard: {e}")
                return jsonify({'error': 'An error occurred'}), 500

    @app.route('/hospital/approve_request/<request_id>', methods=['POST'])
    async def approve_request(request_id):
        if 'hospital_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            hospital = hospitals_collection.find_one({'_id': ObjectId(session['hospital_id'])})
            blood_request = requests_collection.find_one({'_id': ObjectId(request_id), 'hospital_name': hospital['name']})
            if not blood_request:
                return jsonify({'error': 'Request not found or not authorized'}), 404
            requests_collection.update_one(
                {'_id': ObjectId(request_id)},
                {'$set': {'status': 'approved', 'approved_by_hospital': True}}
            )
            patient = users_collection.find_one({'chat_id': blood_request['patient_chat_id']})
            if not patient:
                logger.error(f"Patient not found for chat_id {blood_request['patient_chat_id']}")
                return jsonify({'error': 'Patient not found'}), 404

            # Send notifications with retry logic
            async def send_notifications():
                # Notify patient
                success = await send_message_with_retry(
                    application.bot,
                    blood_request['patient_chat_id'],
                    f"Your blood request for {blood_request['blood_group']} has been approved by {hospital['name']}. Donors have been notified."
                )
                if not success:
                    logger.error(f"Failed to notify patient {blood_request['patient_chat_id']} after {3} attempts")

                # Notify verified donors in the hospital's city with matching blood group
                for donor in users_collection.find({
                    'role': 'DONOR',
                    'blood_group': blood_request['blood_group'],
                    'city': hospital['city'],  # Match hospital city
                    'verified': True
                }):
                    success = await send_message_with_retry(
                        application.bot,
                        donor['chat_id'],
                        (
                            f"Urgent: A patient in {hospital['city']} needs {blood_request['blood_group']} blood "
                            f"({blood_request['units_needed']} units, {blood_request['urgency'].lower()}, by {blood_request['time_needed']}). "
                            f"Contact: {patient['name']} ({patient['contact_number']}). "
                            f"Reply with 'accept {request_id}' or 'reject {request_id}'."
                        )
                    )
                    if not success:
                        logger.error(f"Failed to notify donor {donor['chat_id']} after {3} attempts")

            await send_notifications()
            return jsonify({'message': 'Request approved and notifications sent'}), 200
        except Exception as e:
            logger.error(f"Error approving request {request_id}: {e}")
            return jsonify({'error': 'An error occurred'}), 500

    @app.route('/hospital/reject_request/<request_id>', methods=['POST'])
    async def reject_request(request_id):
        if 'hospital_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            hospital = hospitals_collection.find_one({'_id': ObjectId(session['hospital_id'])})
            blood_request = requests_collection.find_one({'_id': ObjectId(request_id), 'hospital_name': hospital['name']})
            if not blood_request:
                return jsonify({'error': 'Request not found or not authorized'}), 404
            requests_collection.update_one(
                {'_id': ObjectId(request_id)},
                {'$set': {'status': 'rejected', 'approved_by_hospital': False}}
            )
            success = await send_message_with_retry(
                application.bot,
                blood_request['patient_chat_id'],
                f"Your blood request for {blood_request['blood_group']} was rejected by {hospital['name']}. Please contact the hospital for details."
            )
            if not success:
                logger.error(f"Failed to notify patient {blood_request['patient_chat_id']} after {3} attempts")
            return jsonify({'message': 'Request rejected'}), 200
        except Exception as e:
            logger.error(f"Error rejecting request {request_id}: {e}")
            return jsonify({'error': 'An error occurred'}), 500

    @app.route('/hospital/verify_donor/<donor_id>', methods=['POST'])
    async def verify_donor(donor_id):
        if 'hospital_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            hospital = hospitals_collection.find_one({'_id': ObjectId(session['hospital_id'])})
            donor = users_collection.find_one({'_id': ObjectId(donor_id), 'role': 'DONOR', 'city': hospital['city']})
            if not donor:
                return jsonify({'error': 'Donor not found or not in your city'}), 404
            users_collection.update_one(
                {'_id': ObjectId(donor_id)},
                {'$set': {'verified': True}}
            )
            success = await send_message_with_retry(
                application.bot,
                donor['chat_id'],
                f"✅ Your donor profile has been verified by {hospital['name']}! You can now receive blood request notifications."
            )
            if not success:
                logger.error(f"Failed to notify donor {donor['chat_id']} after {3} attempts")
            return jsonify({'message': f"Donor {donor['name']} verified successfully"}), 200
        except Exception as e:
            logger.error(f"Error verifying donor {donor_id}: {e}")
            return jsonify({'error': 'An error occurred'}), 500

    @app.route('/login', methods=['GET', 'POST'])
    def user_login():
        if request.method == 'POST':
            try:
                phone_number = request.form.get('phone_number')
                password = request.form.get('password')
                if not phone_number or not password:
                    return jsonify({'error': 'Phone number and password are required'}), 400
                user = get_user_by_phone(phone_number)
                if user and verify_password(password, user['password_hash']) and user.get('verified', False):
                    session['user_id'] = str(user['_id'])
                    return redirect(url_for('user_dashboard'))
                return jsonify({'error': 'Invalid phone number, password, or unverified user'}), 401
            except Exception as e:
                logger.error(f"Error in user login: {e}")
                return jsonify({'error': 'An error occurred during login'}), 500
        return render_template('login.html')

    @app.route('/dashboard')
    async def user_dashboard():
        if 'user_id' not in session:
            return redirect(url_for('user_login'))
        try:
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            if not user:
                session.pop('user_id', None)
                return redirect(url_for('user_login'))
            if user['role'] == 'DONOR':
                requests = list(requests_collection.find({
                    'status': 'approved',
                    'blood_group': user['blood_group'],
                    'city': user['city']
                }))
                enriched_requests = []
                for req in requests:
                    patient = users_collection.find_one({'chat_id': req['patient_chat_id']})
                    if patient:
                        req['name'] = patient['name']
                        req['contact_number'] = patient['contact_number']
                        req['hospital_location'] = f"{req['city']}, {req['district']}, {req['state']}"
                    else:
                        req['name'] = 'Unknown'
                        req['contact_number'] = 'N/A'
                        req['hospital_location'] = f"{req['city']}, {req['district']}, {req['state']}"
                    enriched_requests.append(req)
                # Enrich reviews with patient names
                enriched_reviews = []
                for review in user.get('reviews', []):
                    patient = users_collection.find_one({'chat_id': review['from_chat_id']})
                    review_copy = review.copy()  # Avoid modifying original review
                    review_copy['patient_name'] = patient['name'] if patient else 'Anonymous'
                    enriched_reviews.append(review_copy)
                user['reviews'] = enriched_reviews
                return render_template('donor_dashboard.html', user=user, requests=enriched_requests)
            else:
                blood_request = requests_collection.find_one({
                    'patient_chat_id': user['chat_id'],
                    'status': {'$in': ['pending', 'approved']}
                })
                donors = list(users_collection.find({
                    'role': 'DONOR',
                    'blood_group': user['blood_group'],
                    'city': user['city'],
                    'verified': True
                }))
                if blood_request:
                    blood_request['hospital_location'] = f"{blood_request['city']}, {blood_request['district']}, {blood_request['state']}"
                return render_template('patient_dashboard.html', user=user, blood_request=blood_request, donors=donors)
        except Exception as e:
            logger.error(f"Error in user dashboard: {e}", exc_info=True)
            return jsonify({'error': 'An error occurred'}), 500

    @app.route('/admin', methods=['GET', 'POST'])
    def admin_page():
        if request.method == 'POST':
            try:
                password = request.form.get('password')
                if password != ADMIN_PASSWORD:
                    return jsonify({'error': 'Invalid admin password'}), 401
                session['admin'] = True
                # Fall-through to GET logic after successful POST login
            except Exception as e:
                logger.error(f"Error in admin login POST: {e}")
                return jsonify({'error': 'An error occurred during login'}), 500

        if session.get('admin'):
            try:
                donors = list(users_collection.find({'role': 'DONOR'}))
                patients = list(users_collection.find({'role': 'PATIENT'}))
                enriched_patients = []
                for patient in patients:
                    # Initialize default values
                    patient_copy = patient.copy() # Work on a copy to avoid modifying original cursor object unexpectedly
                    patient_copy['units_needed'] = 'N/A'
                    patient_copy['urgency'] = 'N/A'
                    patient_copy['hospital_location'] = 'N/A'
                    patient_copy['hospital_name'] = patient_copy.get('hospital_name', 'N/A')
                    patient_copy['blood_group'] = patient_copy.get('blood_group', 'N/A')

                    chat_id = patient_copy.get('chat_id')
                    if chat_id:
                        request_data = requests_collection.find_one({'patient_chat_id': chat_id})
                        if request_data:
                            patient_copy['units_needed'] = request_data.get('units_needed', 'N/A')
                            patient_copy['urgency'] = request_data.get('urgency', 'N/A')
                            patient_copy['hospital_location'] = f"{request_data.get('city', 'N/A')}, {request_data.get('district', 'N/A')}, {request_data.get('state', 'N/A')}"
                            patient_copy['hospital_name'] = request_data.get('hospital_name', patient_copy['hospital_name'])
                            patient_copy['blood_group'] = request_data.get('blood_group', patient_copy['blood_group'])
                    enriched_patients.append(patient_copy)

                hospitals = list(hospitals_collection.find())
                requests = list(requests_collection.find())
                return render_template('admin.html', donors=donors, patients=enriched_patients, hospitals=hospitals, requests=requests)
            except Exception as e:
                logger.error(f"Error in admin page GET: {e}", exc_info=True)
                return jsonify({'error': 'An error occurred'}), 500
        return render_template('admin_login.html')

    @app.route('/image/<file_id>')
    def serve_image(file_id):
        try:
            file = fs.get(ObjectId(file_id))
            return send_file(io.BytesIO(file.read()), mimetype='image/jpeg')
        except Exception as e:
            logger.error(f"Error serving image {file_id}: {e}")
            return jsonify({'error': 'Image not found'}), 404
   


   
        # ----- FIND HOSPITAL -----
    @app.route("/find-hospital", methods=["GET"])
    def find_hospital():
        try:
            # Distinct values for filter dropdowns (remove None/empty and sort)
            all_cities = sorted([c for c in hospitals_collection.distinct("city") if c])
            all_states = sorted([s for s in hospitals_collection.distinct("state") if s])
            all_districts = sorted([d for d in hospitals_collection.distinct("district") if d])

            # Selected filters from query params
            selected_city = request.args.get("city") or ""
            selected_state = request.args.get("state") or ""
            selected_district = request.args.get("district") or ""

            # Build query
            query = {}
            if selected_city:
                query["city"] = selected_city
            if selected_state:
                query["state"] = selected_state
            if selected_district:
                query["district"] = selected_district

            # Fetch hospitals (if no filters, show all)
            hospitals = list(hospitals_collection.find(query))

            return render_template(
                "find_hospital.html",
                hospitals=hospitals,
                all_cities=all_cities,
                all_states=all_states,
                all_districts=all_districts,
                selected_city=selected_city,
                selected_state=selected_state,
                selected_district=selected_district
            )
        except Exception as e:
            logger.error(f"Error in find_hospital route: {e}", exc_info=True)
            return jsonify({"error": "An error occurred fetching hospitals"}), 500


    # ----- FIND DONOR -----
    @app.route("/find-donor", methods=["GET"])
    def find_donor():
        try:
            # Distinct values for donor dropdowns (only from users that are DONORs)
            all_cities = sorted([c for c in users_collection.distinct("city", {"role": "DONOR"}) if c])
            all_states = sorted([s for s in users_collection.distinct("state", {"role": "DONOR"}) if s])
            all_districts = sorted([d for d in users_collection.distinct("district", {"role": "DONOR"}) if d])
            all_blood_groups = sorted([bg for bg in users_collection.distinct("blood_group", {"role": "DONOR"}) if bg])

            # Selected filters from query params
            selected_city = request.args.get("city") or ""
            selected_state = request.args.get("state") or ""
            selected_district = request.args.get("district") or ""
            selected_blood_group = request.args.get("blood_group") or ""

            # Build MongoDB query (always filter role = "DONOR")
            query = {"role": "DONOR"}
            if selected_city:
                query["city"] = selected_city
            if selected_state:
                query["state"] = selected_state
            if selected_district:
                query["district"] = selected_district
            if selected_blood_group:
                query["blood_group"] = selected_blood_group

            # Fetch donors
            donors = list(users_collection.find(query))

            # Optional: log the number of donors found for debugging
            logger.debug(f"find_donor: query={query} -> {len(donors)} donors")

            return render_template(
                "find_donor.html",
                donors=donors,
                all_cities=all_cities,
                all_states=all_states,
                all_districts=all_districts,
                all_blood_groups=all_blood_groups,
                selected_city=selected_city,
                selected_state=selected_state,
                selected_district=selected_district,
                selected_blood_group=selected_blood_group
            )
        except Exception as e:
            logger.error(f"Error in find_donor route: {e}", exc_info=True)
            return jsonify({"error": "An error occurred fetching donors"}), 500

   
    


  


